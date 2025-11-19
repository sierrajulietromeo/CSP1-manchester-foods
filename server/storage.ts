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

    // Sample customer
    const customerId = randomUUID();
    this.users.set(customerId, {
      id: customerId,
      username: "demo",
      password: "demo123", // VULNERABILITY: Plaintext password
      email: "demo@restaurant.com",
      companyName: "Demo Restaurant",
      contactPerson: "John Smith",
      phone: "0161 555 0123",
      address: "123 Main St, Manchester M1 1AA",
      role: "customer",
      bio: "Popular restaurant in Manchester city centre",
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
    });
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
