import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import session from "express-session";
import { readFileSync } from "fs";
import multer from "multer";
import path from "path";
import fs from "fs";

// Configure multer for file uploads
// VULNERABILITY: No file type validation, no size limits
const storageConfig = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = "uploads";
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // VULNERABILITY: Using original filename allows path traversal or overwriting critical files
    // Ideally should use a random ID
    cb(null, file.originalname);
  },
});

const upload = multer({ storage: storageConfig });

// VULNERABILITY: Predictable session ID generation
let sessionCounter = 1000;
function generatePredictableSessionId(): string {
  // VULNERABILITY: Sequential, predictable session IDs
  return `sess_${sessionCounter++}_${Date.now()}`;
}

// VULNERABILITY: Storing session in memory - insecure for production
// VULNERABILITY: Predictable session secret
const sessionMiddleware = session({
  secret: "manchester-fresh-2024", // VULNERABILITY: Hardcoded weak secret
  resave: false,
  saveUninitialized: false,
  genid: () => generatePredictableSessionId(), // VULNERABILITY: Predictable session IDs
  cookie: {
    secure: false, // VULNERABILITY: Not requiring HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
});

// Extend Express session type
declare module "express-session" {
  interface SessionData {
    userId?: string;
    username?: string;
  }
}

export async function registerRoutes(app: Express): Promise<Server> {
  // VULNERABILITY: No security headers middleware
  // Missing: helmet, CORS restrictions, CSP, X-Frame-Options, etc.

  // VULNERABILITY: Permissive CORS allowing CSRF attacks
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  app.use(sessionMiddleware);

  // VULNERABILITY: Verbose error handling exposing system details
  app.use((err: any, req: Request, res: Response, next: any) => {
    console.error(err.stack);
    res.status(500).json({
      error: err.message,
      stack: err.stack, // VULNERABILITY: Exposing stack traces
      systemInfo: {
        node: process.version,
        platform: process.platform,
      },
    });
  });

  // Authentication endpoints - VULNERABILITIES: SQL Injection, No rate limiting, Plaintext passwords

  app.post("/api/register", async (req, res) => {
    try {
      const { username, password, email, companyName, contactPerson, phone, address, bio } = req.body;

      // VULNERABILITY: Weak password validation (no minimum length, complexity)
      if (!username || !password || !email) {
        return res.status(400).json({ error: "Missing required fields" });
      }

      // VULNERABILITY: SQL Injection (Real - uses vulnerable storage method)
      const existing = await storage.getUserByUsername(username);
      if (existing) {
        return res.status(400).json({ error: "Username already exists" });
      }

      // VULNERABILITY: Storing password in plaintext
      const user = await storage.createUser({
        username,
        password, // Should be hashed!
        email,
        companyName,
        contactPerson,
        phone,
        address,
        bio,
      });

      res.json({ message: "User created successfully", userId: user.id });
    } catch (error: any) {
      // VULNERABILITY: Verbose error messages
      res.status(500).json({ error: error.message, details: error.toString() });
    }
  });

  app.post("/api/login", async (req, res) => {
    try {
      const { username, password } = req.body;

      // VULNERABILITY: No rate limiting - brute force attacks possible
      if (!username || !password) {
        return res.status(400).json({ error: "Missing credentials" });
      }

      // VULNERABILITY: SQL Injection
      // The storage method now contains the actual vulnerable SQL query
      const user = await storage.getUserByCredentials(username, password);

      if (!user) {
        return res.status(401).json({
          error: "Invalid credentials",
          hint: "Try admin/admin123 for demo",
        });
      }

      req.session.userId = user.id;
      req.session.username = user.username;

      res.json({
        message: "Login successful",
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.post("/api/logout", async (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: "Logout failed" });
      }
      res.json({ message: "Logged out successfully" });
    });
  });

  // Get current user - VULNERABILITY: No authentication check in some routes
  app.get("/api/user", async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const user = await storage.getUser(req.session.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  });

  // VULNERABILITY: IDOR - No authorization check, can access any user's data
  app.get("/api/user/:id", async (req, res) => {
    const user = await storage.getUser(req.params.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    // Should check if req.session.userId === req.params.id
    res.json(user);
  });

  // Update user profile - VULNERABILITY: No CSRF protection, XSS in bio field
  app.patch("/api/user", async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    // VULNERABILITY: XSS - bio field not sanitized, will be rendered as HTML
    const updates: any = {};
    if (req.body.email !== undefined) updates.email = req.body.email;
    if (req.body.companyName !== undefined) updates.companyName = req.body.companyName;
    if (req.body.contactPerson !== undefined) updates.contactPerson = req.body.contactPerson;
    if (req.body.phone !== undefined) updates.phone = req.body.phone;
    if (req.body.address !== undefined) updates.address = req.body.address;
    if (req.body.bio !== undefined) updates.bio = req.body.bio; // VULNERABILITY: Stored XSS vector

    const updated = await storage.updateUser(req.session.userId, updates);

    res.json(updated);
  });

  // Products endpoints - VULNERABILITY: SQL Injection in search
  app.get("/api/products", async (req, res) => {
    try {
      const { search } = req.query;

      if (search) {
        // VULNERABILITY: SQL Injection in search
        // Real SQL: SELECT * FROM products WHERE name LIKE '%${search}%'
        // Attack: search=' UNION SELECT * FROM users--

        const products = await storage.searchProducts(search as string);
        return res.json(products);
      }

      const products = await storage.getAllProducts();
      res.json(products);
    } catch (error: any) {
      // VULNERABILITY: Return 200 with empty array on SQL errors
      // This allows SQLmap to detect the injection (500 errors confuse it)
      // In a real app, this would hide SQL errors from attackers
      res.status(200).json([]);
    }
  });

  app.get("/api/products/:id", async (req, res) => {
    const product = await storage.getProduct(req.params.id);
    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }
    res.json(product);
  });

  // Orders endpoints - VULNERABILITIES: IDOR, CSRF, No input validation
  app.get("/api/orders", async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    // Check if user is admin
    const user = await storage.getUser(req.session.userId);
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    // Admin sees ALL orders with customer info, customers see only their own
    if (user.role === "admin") {
      const allOrders = await storage.getAllOrders();

      // Enrich orders with customer information for admin view
      const enrichedOrders = await Promise.all(
        allOrders.map(async (order) => {
          const customer = await storage.getUser(order.userId);
          return {
            ...order,
            customerName: customer?.companyName || customer?.username || "Unknown",
            customerContact: customer?.contactPerson,
          };
        })
      );

      res.json(enrichedOrders);
    } else {
      const orders = await storage.getUserOrders(req.session.userId);
      res.json(orders);
    }
  });

  // VULNERABILITY: IDOR - Can access any order by ID
  app.get("/api/orders/:id", async (req, res) => {
    const order = await storage.getOrder(req.params.id);
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }
    // Should check if order.userId === req.session.userId
    res.json(order);
  });

  // VULNERABILITY: No CSRF protection, insufficient input validation
  app.post("/api/orders", async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    // Check if user is admin - admins cannot place orders
    const user = await storage.getUser(req.session.userId);
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    if (user.role === "admin") {
      return res.status(403).json({ error: "Administrators cannot place orders" });
    }

    try {
      const { items, totalAmount, deliveryAddress, deliveryDate, notes } = req.body;

      // VULNERABILITY: No validation on quantities (could be negative)
      // VULNERABILITY: No validation on totalAmount (could be tampered)
      // VULNERABILITY: XSS in notes field

      if (!items || items.length === 0) {
        return res.status(400).json({ error: "No items in order" });
      }

      const order = await storage.createOrder({
        userId: req.session.userId,
        status: "pending",
        totalAmount,
        deliveryAddress,
        deliveryDate,
        notes, // VULNERABILITY: Stored XSS vector
      });

      // Create order items
      for (const item of items) {
        await storage.createOrderItem({
          orderId: order.id,
          productId: item.productId,
          productName: item.productName,
          quantity: item.quantity, // VULNERABILITY: No validation (could be negative)
          pricePerUnit: item.pricePerUnit,
          subtotal: item.subtotal,
        });
      }

      res.json(order);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Contact form - VULNERABILITY: XSS in message field, no rate limiting
  app.post("/api/contact", async (req, res) => {
    try {
      const { name, email, company, message } = req.body;

      if (!name || !email || !message) {
        return res.status(400).json({ error: "Missing required fields" });
      }

      // VULNERABILITY: No email validation, XSS in message field
      const contact = await storage.createContactSubmission({
        name,
        email,
        company,
        message, // VULNERABILITY: Stored XSS vector
      });

      res.json({ message: "Contact form submitted", id: contact.id });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // VULNERABILITY: Exposed admin endpoint with no authentication
  app.get("/api/admin/contacts", async (req, res) => {
    // Should check if user is admin!
    const contacts = await storage.getAllContactSubmissions();
    res.json(contacts);
  });

  // VULNERABILITY: Information disclosure - exposed configuration endpoint
  app.get("/api/config", (req, res) => {
    res.json({
      environment: process.env.NODE_ENV || "development",
      version: "1.0.0",
      database: "in-memory",
      sessionSecret: "manchester-fresh-2024", // VULNERABILITY: Exposing secrets
      adminUsername: "admin", // VULNERABILITY: Leaking credentials
    });
  });

  // VULNERABILITY: Exposed .git directory simulation
  // NOTE: This is simulated because exposing the actual .git directory of the container/project
  // would be an architectural risk and might not exist in all environments.
  app.get("/.git/config", (req, res) => {
    res.set("Content-Type", "text/plain");
    res.send(`[core]
  repositoryformatversion = 0
  filemode = true
  bare = false
  logallrefupdates = true
[remote "origin"]
  url = https://github.com/manchesterfresh/vulnerable-app.git
  fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
  remote = origin
  merge = refs/heads/main
# VULNERABILITY: Exposed git repository
# Database credentials: postgres://admin:SecretPassword123@localhost:5432/freshfoods
`);
  });

  // VULNERABILITY: robots.txt revealing hidden paths
  app.get("/robots.txt", (req, res) => {
    res.set("Content-Type", "text/plain");
    res.send(`User-agent: *
Disallow: /api/admin
Disallow: /.git
Disallow: /backup
Disallow: /instructor
Disallow: /.env
Disallow: /data/customers.txt
`);
  });

  // VULNERABILITY: Exposed customer data file with PII and financial information
  app.get("/data/customers.txt", (req, res) => {
    res.set("Content-Type", "text/plain");
    res.send(`MANCHESTER FRESH FOODS - CUSTOMER DATABASE BACKUP
Generated: 15 November 2025
CONFIDENTIAL - INTERNAL USE ONLY

=== CUSTOMER ACCOUNTS WITH CURRENT BALANCES ===

ACCOUNT: ACC-1001
Company: The Pub Company Ltd
Contact: Sarah Johnson
Email: orders@thepubcompany.co.uk
Phone: 0161 789 4521
Address: 45 Deansgate, Manchester M3 2AY
Current Balance: £1,247.50 (30 days overdue)
Credit Limit: £5,000.00
Last Payment: 28 October 2025 - £2,100.00

ACCOUNT: ACC-1002
Company: Bella Italia Restaurant
Contact: Marco Rossi
Email: procurement@bella-italia.co.uk
Phone: 0161 832 6574
Address: 78 King Street, Manchester M2 4WQ
Current Balance: £0.00
Credit Limit: £3,000.00
Last Payment: 10 November 2025 - £987.40

ACCOUNT: ACC-1003
Company: Green Leaf Café
Contact: Emma Williams
Email: manager@greenleafcafe.com
Phone: 0161 955 3344
Address: 12 Oxford Road, Manchester M1 5QA
Current Balance: £342.80
Credit Limit: £2,000.00
Last Payment: 1 November 2025 - £654.20

ACCOUNT: ACC-1004
Company: Royal Curry House
Contact: Raj Patel
Email: kitchen@royalcurryhouse.co.uk
Phone: 0161 273 8899
Address: 156 Wilmslow Road, Manchester M14 5LH
Current Balance: £0.00
Credit Limit: £4,000.00
Last Payment: 12 November 2025 - £1,456.30

ACCOUNT: ACC-1005
Company: Manchester City Hotel
Contact: David Chen
Email: catering@manchestercityhotel.com
Phone: 0161 234 9876
Address: 200 Portland Street, Manchester M1 3HU
Current Balance: £3,876.40 (60 days overdue - CREDIT HOLD)
Credit Limit: £10,000.00
Last Payment: 18 September 2025 - £5,243.00

ACCOUNT: ACC-1006
Company: The Northern Quarter Bistro
Contact: Rachel Green
Email: manager@nqbistro.co.uk
Phone: 0161 834 5567
Address: 34 Oldham Street, Manchester M1 1JN
Current Balance: £567.90
Credit Limit: £2,500.00
Last Payment: 5 November 2025 - £1,234.50

ACCOUNT: ACC-1007
Company: Spinningfields Grill
Contact: Tom Anderson
Email: procurement@spinningfieldsgrill.com
Phone: 0161 819 2200
Address: 1 Hardman Square, Manchester M3 3EB
Current Balance: £0.00
Credit Limit: £6,000.00
Last Payment: 13 November 2025 - £2,987.60

=== ADMIN CREDENTIALS ===
Username: admin
Password: admin123
Email: admin@manchesterfresh.co.uk
Phone: 0161 234 5678

=== NOTES ===
- ACC-1005 (City Hotel) is on credit hold due to non-payment
- ACC-1001 (Pub Company) requires follow-up call for overdue balance
- All customers on NET 30 payment terms
- Database last synced: 15/11/2025 03:45 GMT

--- END OF REPORT ---
`);
  });

  // VULNERABILITY: Server-Side Request Forgery (SSRF) in document fetching
  app.post("/api/fetch-document", async (req, res) => {
    try {
      const { url } = req.body;

      if (!url) {
        return res.status(400).json({ error: "URL required" });
      }

      // VULNERABILITY: No URL validation - can fetch internal resources
      // Attack: url = "http://localhost:5000/api/config" or "file:///etc/passwd"
      const response = await fetch(url);
      const data = await response.text();

      res.json({
        url,
        content: data,
        warning: "VULNERABILITY: SSRF - fetches arbitrary URLs",
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // VULNERABILITY: Local File Inclusion (LFI) in document viewer
  app.get("/api/view-document", (req, res) => {
    const { file } = req.query;

    if (!file) {
      return res.status(400).json({ error: "File parameter required" });
    }

    // VULNERABILITY: Path traversal - no sanitization
    // Attack: file=../../../../etc/passwd
    try {
      const content = readFileSync(file as string, "utf-8");

      res.json({
        file,
        content,
        warning: "VULNERABILITY: LFI - reads arbitrary files",
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message, hint: "Try ../../../../etc/passwd" });
    }
  });

  // VULNERABILITY: XML External Entity (XXE) injection
  // NOTE: This is simulated because Node.js XML parsers (like sax-js, xml2js) are generally safe
  // from XXE by default or don't support external entities in the same way as Java/PHP parsers.
  app.post("/api/import-order", async (req, res) => {
    try {
      const { xml } = req.body;

      if (!xml) {
        return res.status(400).json({ error: "XML required" });
      }

      // VULNERABILITY: Unsafe XML parsing without disabling external entities
      // Attack: Include malicious XML with external entity references
      // Example: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><order>&xxe;</order>

      res.json({
        message: "Order import functionality - VULNERABILITY: XXE injection possible",
        xmlReceived: xml,
        warning: "XML parser would process external entities in production (Simulated in Node.js)",
        hint: "Try: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><order>&xxe;</order>",
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // VULNERABILITY: File upload with no restrictions
  app.post("/api/upload", upload.single("file"), (req, res) => {
    // VULNERABILITY: No file type validation, size limits, or content scanning
    // The file is actually saved to disk!

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    res.json({
      message: "File uploaded successfully",
      filename: req.file.originalname,
      path: req.file.path,
      size: req.file.size,
      warning: "VULNERABILITY: No validation performed. Malicious files accepted.",
    });
  });

  const httpServer = createServer(app);

  return httpServer;
}
