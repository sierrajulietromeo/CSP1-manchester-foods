import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import session from "express-session";

// VULNERABILITY: Storing session in memory - insecure for production
// VULNERABILITY: Predictable session secret
const sessionMiddleware = session({
  secret: "manchester-fresh-2024", // VULNERABILITY: Hardcoded weak secret
  resave: false,
  saveUninitialized: false,
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

      // VULNERABILITY: SQL Injection (simulated - using string concatenation logic)
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

      // VULNERABILITY: SQL Injection simulation
      // In a real SQL DB, this would be: SELECT * FROM users WHERE username = '${username}' AND password = '${password}'
      // Attack: username = "admin' OR '1'='1" would bypass authentication
      
      // Simulating SQL injection vulnerability
      if (username.includes("' OR '1'='1") || username.includes("' or '1'='1")) {
        // SQL injection successful - log in as first user (usually admin)
        const users = await storage.getAllUsers();
        const user = users[0]; // Return first user (admin)
        
        if (user) {
          req.session.userId = user.id;
          req.session.username = user.username;
          
          return res.json({
            message: "Login successful",
            user: {
              id: user.id,
              username: user.username,
              email: user.email,
              role: user.role,
            },
          });
        }
      }

      const user = await storage.getUserByUsername(username);

      // VULNERABILITY: Plaintext password comparison
      if (!user || user.password !== password) {
        // VULNERABILITY: Information disclosure - different messages for invalid user vs wrong password
        return res.status(401).json({ 
          error: user ? "Incorrect password" : "User not found",
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
    const { email, companyName, contactPerson, phone, address, bio } = req.body;

    const updated = await storage.updateUser(req.session.userId, {
      email,
      companyName,
      contactPerson,
      phone,
      address,
      bio, // VULNERABILITY: Stored XSS vector
    });

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
      res.status(500).json({ error: error.message });
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

    const orders = await storage.getUserOrders(req.session.userId);
    res.json(orders);
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
  app.get("/.git/config", (req, res) => {
    res.set("Content-Type", "text/plain");
    res.send(`[core]
  repositoryformatversion = 0
  filemode = true
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
`);
  });

  const httpServer = createServer(app);

  return httpServer;
}
