import Database from "better-sqlite3";
import { randomUUID } from "crypto";

export function initializeDatabase(dbPath: string = "database.sqlite"): Database.Database {
  const db = new Database(dbPath);
  
  // Enable foreign keys
  db.pragma("foreign_keys = ON");
  
  // Create tables with SQLite syntax
  createTables(db);
  
  // Seed database with test data
  seedDatabase(db);
  
  return db;
}

function createTables(db: Database.Database) {
  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      email TEXT NOT NULL,
      company_name TEXT,
      contact_person TEXT,
      phone TEXT,
      address TEXT,
      role TEXT NOT NULL DEFAULT 'customer',
      bio TEXT
    )
  `);

  // Products table
  db.exec(`
    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      category TEXT NOT NULL,
      unit TEXT NOT NULL,
      price_per_unit REAL NOT NULL,
      image_url TEXT,
      stock INTEGER NOT NULL DEFAULT 100
    )
  `);

  // Orders table
  db.exec(`
    CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      order_number TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL DEFAULT 'pending',
      total_amount REAL NOT NULL,
      delivery_date TEXT,
      delivery_address TEXT,
      notes TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  // Order items table
  db.exec(`
    CREATE TABLE IF NOT EXISTS order_items (
      id TEXT PRIMARY KEY,
      order_id TEXT NOT NULL,
      product_id TEXT NOT NULL,
      product_name TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      price_per_unit REAL NOT NULL,
      subtotal REAL NOT NULL
    )
  `);

  // Reviews table
  db.exec(`
    CREATE TABLE IF NOT EXISTS reviews (
      id TEXT PRIMARY KEY,
      product_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      rating INTEGER NOT NULL,
      comment TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  // Contact submissions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS contact_submissions (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      company TEXT,
      message TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
}

function seedDatabase(db: Database.Database): void {
  // Check if database is already seeded
  const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get() as { count: number };
  if (userCount.count > 0) {
    console.log(`ℹ️  Database already seeded (${userCount.count} users found), skipping seed`);
    return; // Already seeded
  }

  console.log("🌱 Seeding database with test data...");

  // Insert users (admin + 6 customers)
  const users = [
    { id: randomUUID(), username: "admin", password: "admin123", role: "admin", companyName: "Manchester Fresh Foods", contactPerson: "Admin User", email: "admin@manchesterfresh.co.uk", phone: "0161-555-0100", address: "123 Market Street, Manchester M1 1AA", bio: null },
    { id: randomUUID(), username: "thepubco", password: "welcome123", role: "customer", companyName: "The Pub Company Ltd", contactPerson: "Sarah Mitchell", email: "sarah@pubco.co.uk", phone: "0161-555-0101", address: "45 Deansgate, Manchester M3 2AY", bio: null },
    { id: randomUUID(), username: "bella_italia", password: "pasta2024", role: "customer", companyName: "Bella Italia Restaurant", contactPerson: "Marco Romano", email: "marco@bellaitalia.co.uk", phone: "0161-555-0102", address: "78 King Street, Manchester M2 4WQ", bio: null },
    { id: randomUUID(), username: "green_leaf", password: "healthy1", role: "customer", companyName: "Green Leaf Café", contactPerson: "Emma Thompson", email: "emma@greenleaf.co.uk", phone: "0161-555-0103", address: "12 Portland Street, Manchester M1 3HU", bio: null },
    { id: randomUUID(), username: "royal_curry", password: "spice99", role: "customer", companyName: "Royal Curry House", contactPerson: "Rajesh Kumar", email: "rajesh@royalcurry.co.uk", phone: "0161-555-0104", address: "56 Wilmslow Road, Manchester M14 5TQ", bio: null },
    { id: randomUUID(), username: "cityhotel", password: "hotel2024", role: "customer", companyName: "Manchester City Hotel", contactPerson: "David Anderson", email: "david@cityhot el.co.uk", phone: "0161-555-0105", address: "89 Piccadilly, Manchester M1 2AP", bio: null },
    { id: randomUUID(), username: "spanish_tapas", password: "tapas123", role: "customer", companyName: "Spanish Tapas Bar", contactPerson: "Carlos Fernandez", email: "carlos@spanishtapas.co.uk", phone: "0161-555-0106", address: "34 Bridge Street, Manchester M3 3BT", bio: null },
  ];

  const insertUser = db.prepare(`
    INSERT INTO users (id, username, password, role, company_name, contact_person, email, phone, address, bio)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  users.forEach(user => {
    insertUser.run(user.id, user.username, user.password, user.role, user.companyName, user.contactPerson, user.email, user.phone, user.address, user.bio);
  });

  // Insert products
  const products = [
    { id: randomUUID(), name: "Organic Tomatoes", category: "Vegetables", price: 2.50, unit: "kg", description: "Fresh organic vine tomatoes", imageUrl: null, stock: 150 },
    { id: randomUUID(), name: "British Potatoes", category: "Vegetables", price: 1.20, unit: "kg", description: "Locally sourced Maris Piper potatoes", imageUrl: null, stock: 300 },
    { id: randomUUID(), name: "Fresh Carrots", category: "Vegetables", price: 1.80, unit: "kg", description: "Crunchy orange carrots", imageUrl: null, stock: 200 },
    { id: randomUUID(), name: "Iceberg Lettuce", category: "Salad", price: 1.50, unit: "head", description: "Crisp iceberg lettuce heads", imageUrl: null, stock: 100 },
    { id: randomUUID(), name: "Red Onions", category: "Vegetables", price: 1.40, unit: "kg", description: "Sweet red onions", imageUrl: null, stock: 180 },
    { id: randomUUID(), name: "Green Beans", category: "Vegetables", price: 3.20, unit: "kg", description: "Fresh green beans", imageUrl: null, stock: 120 },
    { id: randomUUID(), name: "Broccoli Crowns", category: "Vegetables", price: 2.80, unit: "kg", description: "Fresh broccoli crowns", imageUrl: null, stock: 90 },
    { id: randomUUID(), name: "Sweet Peppers", category: "Vegetables", price: 4.50, unit: "kg", description: "Mixed colour bell peppers", imageUrl: null, stock: 110 },
    { id: randomUUID(), name: "Mushrooms", category: "Vegetables", price: 3.80, unit: "kg", description: "Button mushrooms", imageUrl: null, stock: 85 },
    { id: randomUUID(), name: "Cucumbers", category: "Salad", price: 1.20, unit: "each", description: "Fresh cucumbers", imageUrl: null, stock: 140 },
    { id: randomUUID(), name: "Spinach", category: "Salad", price: 2.90, unit: "kg", description: "Fresh baby spinach", imageUrl: null, stock: 75 },
    { id: randomUUID(), name: "Courgettes", category: "Vegetables", price: 2.40, unit: "kg", description: "Green courgettes", imageUrl: null, stock: 95 },
    { id: randomUUID(), name: "Aubergines", category: "Vegetables", price: 3.50, unit: "kg", description: "Fresh aubergines", imageUrl: null, stock: 70 },
    { id: randomUUID(), name: "Cherry Tomatoes", category: "Salad", price: 4.20, unit: "kg", description: "Sweet cherry tomatoes", imageUrl: null, stock: 130 },
    { id: randomUUID(), name: "Celery", category: "Vegetables", price: 1.80, unit: "bunch", description: "Fresh celery bunches", imageUrl: null, stock: 60 },
    { id: randomUUID(), name: "Leeks", category: "Vegetables", price: 2.60, unit: "kg", description: "Fresh leeks", imageUrl: null, stock: 80 },
    { id: randomUUID(), name: "Rocket Salad", category: "Salad", price: 3.40, unit: "kg", description: "Peppery rocket leaves", imageUrl: null, stock: 65 },
    { id: randomUUID(), name: "Cauliflower", category: "Vegetables", price: 2.20, unit: "head", description: "Fresh cauliflower heads", imageUrl: null, stock: 55 },
    { id: randomUUID(), name: "Spring Onions", category: "Vegetables", price: 1.60, unit: "bunch", description: "Fresh spring onions", imageUrl: null, stock: 90 },
    { id: randomUUID(), name: "Baby Corn", category: "Vegetables", price: 3.90, unit: "kg", description: "Tender baby corn", imageUrl: null, stock: 50 },
  ];

  const insertProduct = db.prepare(`
    INSERT INTO products (id, name, category, price_per_unit, unit, description, image_url, stock)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  products.forEach(product => {
    insertProduct.run(product.id, product.name, product.category, product.price, product.unit, product.description, product.imageUrl, product.stock);
  });

  // Get user and product IDs for creating orders
  const allUsers = db.prepare("SELECT * FROM users WHERE role = 'customer'").all() as any[];
  const allProducts = db.prepare("SELECT * FROM products LIMIT 15").all() as any[];

  // Insert historical orders for first 3 customers
  let orderCounter = 1000;
  
  // The Pub Company orders
  const pubcoUser = allUsers.find(u => u.username === "thepubco");
  if (pubcoUser) {
    const order1Id = randomUUID();
    db.prepare(`
      INSERT INTO orders (id, order_number, user_id, status, delivery_date, delivery_address, notes, created_at, total_amount)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(order1Id, `MFF-${orderCounter++}`, pubcoUser.id, "Delivered", "2024-11-10", "45 Deansgate, Manchester M3 2AY", "Please deliver before 8am", "2024-11-08T10:30:00Z", 156.80);
    
    // Order items for order 1
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order1Id, allProducts[0].id, allProducts[0].name, 20, allProducts[0].price_per_unit, 20 * allProducts[0].price_per_unit);
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order1Id, allProducts[1].id, allProducts[1].name, 50, allProducts[1].price_per_unit, 50 * allProducts[1].price_per_unit);
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order1Id, allProducts[3].id, allProducts[3].name, 15, allProducts[3].price_per_unit, 15 * allProducts[3].price_per_unit);

    const order2Id = randomUUID();
    db.prepare(`
      INSERT INTO orders (id, order_number, user_id, status, delivery_date, delivery_address, notes, created_at, total_amount)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(order2Id, `MFF-${orderCounter++}`, pubcoUser.id, "Delivered", "2024-11-15", "45 Deansgate, Manchester M3 2AY", null, "2024-11-13T09:15:00Z", 203.40);
    
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order2Id, allProducts[2].id, allProducts[2].name, 30, allProducts[2].price_per_unit, 30 * allProducts[2].price_per_unit);
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order2Id, allProducts[4].id, allProducts[4].name, 25, allProducts[4].price_per_unit, 25 * allProducts[4].price_per_unit);

    const order3Id = randomUUID();
    db.prepare(`
      INSERT INTO orders (id, order_number, user_id, status, delivery_date, delivery_address, notes, created_at, total_amount)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(order3Id, `MFF-${orderCounter++}`, pubcoUser.id, "Confirmed", "2024-11-22", "45 Deansgate, Manchester M3 2AY", "Urgent - event catering", "2024-11-18T14:20:00Z", 312.50);
    
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order3Id, allProducts[0].id, allProducts[0].name, 40, allProducts[0].price_per_unit, 40 * allProducts[0].price_per_unit);
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order3Id, allProducts[5].id, allProducts[5].name, 20, allProducts[5].price_per_unit, 20 * allProducts[5].price_per_unit);
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order3Id, allProducts[7].id, allProducts[7].name, 15, allProducts[7].price_per_unit, 15 * allProducts[7].price_per_unit);
  }

  // Bella Italia orders
  const bellaUser = allUsers.find(u => u.username === "bella_italia");
  if (bellaUser) {
    const order4Id = randomUUID();
    db.prepare(`
      INSERT INTO orders (id, order_number, user_id, status, delivery_date, delivery_address, notes, created_at, total_amount)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(order4Id, `MFF-${orderCounter++}`, bellaUser.id, "Delivered", "2024-11-12", "78 King Street, Manchester M2 4WQ", null, "2024-11-10T11:00:00Z", 187.60);
    
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order4Id, allProducts[0].id, allProducts[0].name, 25, allProducts[0].price_per_unit, 25 * allProducts[0].price_per_unit);
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order4Id, allProducts[7].id, allProducts[7].name, 20, allProducts[7].price_per_unit, 20 * allProducts[7].price_per_unit);

    const order5Id = randomUUID();
    db.prepare(`
      INSERT INTO orders (id, order_number, user_id, status, delivery_date, delivery_address, notes, created_at, total_amount)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(order5Id, `MFF-${orderCounter++}`, bellaUser.id, "Processing", "2024-11-20", "78 King Street, Manchester M2 4WQ", "Weekly order", "2024-11-17T10:30:00Z", 245.30);
    
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order5Id, allProducts[1].id, allProducts[1].name, 35, allProducts[1].price_per_unit, 35 * allProducts[1].price_per_unit);
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order5Id, allProducts[3].id, allProducts[3].name, 30, allProducts[3].price_per_unit, 30 * allProducts[3].price_per_unit);
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order5Id, allProducts[8].id, allProducts[8].name, 18, allProducts[8].price_per_unit, 18 * allProducts[8].price_per_unit);
  }

  // Green Leaf Café orders
  const greenLeafUser = allUsers.find(u => u.username === "green_leaf");
  if (greenLeafUser) {
    const order6Id = randomUUID();
    db.prepare(`
      INSERT INTO orders (id, order_number, user_id, status, delivery_date, delivery_address, notes, created_at, total_amount)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(order6Id, `MFF-${orderCounter++}`, greenLeafUser.id, "Delivered", "2024-11-14", "12 Portland Street, Manchester M1 3HU", "Organic products only", "2024-11-12T08:45:00Z", 142.80);
    
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order6Id, allProducts[0].id, allProducts[0].name, 15, allProducts[0].price_per_unit, 15 * allProducts[0].price_per_unit);
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order6Id, allProducts[3].id, allProducts[3].name, 25, allProducts[3].price_per_unit, 25 * allProducts[3].price_per_unit);
    db.prepare(`INSERT INTO order_items (id, order_id, product_id, product_name, quantity, price_per_unit, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(randomUUID(), order6Id, allProducts[10].id, allProducts[10].name, 12, allProducts[10].price_per_unit, 12 * allProducts[10].price_per_unit);
  }

  // Insert reviews
  const reviews = [
    { productId: allProducts[0].id, userId: pubcoUser?.id, username: "thepubco", rating: 5, comment: "Excellent quality tomatoes, our customers love them!" },
    { productId: allProducts[1].id, userId: bellaUser?.id, username: "bella_italia", rating: 4, comment: "Good quality, reliable delivery" },
    { productId: allProducts[3].id, userId: greenLeafUser?.id, username: "green_leaf", rating: 5, comment: "Perfect for our salads, always fresh" },
  ];

  reviews.forEach(review => {
    if (review.userId) {
      db.prepare(`
        INSERT INTO reviews (id, product_id, user_id, username, rating, comment, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(randomUUID(), review.productId, review.userId, review.username, review.rating, review.comment, new Date().toISOString());
    }
  });

  // Insert contact submissions
  const contacts = [
    { name: "James Wilson", email: "james@testcafe.co.uk", company: "Test Café", message: "Interested in wholesale pricing for organic vegetables" },
    { name: "Linda Green", email: "linda@greens.co.uk", company: null, message: "Do you deliver to Salford?" },
  ];

  contacts.forEach(contact => {
    db.prepare(`
      INSERT INTO contact_submissions (id, name, email, company, message, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(randomUUID(), contact.name, contact.email, contact.company, contact.message, new Date().toISOString());
  });

  console.log("✅ Database seeded successfully!");
  console.log(`   - ${users.length} users created`);
  console.log(`   - ${products.length} products created`);
  console.log(`   - 6 historical orders created`);
  console.log(`   - ${reviews.length} reviews created`);
  console.log(`   - ${contacts.length} contact submissions created`);
}

export function resetDatabase(dbPath: string = "database.sqlite"): Database.Database {
  const db = new Database(dbPath);
  
  // Drop all tables
  db.exec(`DROP TABLE IF EXISTS contact_submissions`);
  db.exec(`DROP TABLE IF EXISTS reviews`);
  db.exec(`DROP TABLE IF EXISTS order_items`);
  db.exec(`DROP TABLE IF EXISTS orders`);
  db.exec(`DROP TABLE IF EXISTS products`);
  db.exec(`DROP TABLE IF EXISTS users`);
  
  // Recreate tables
  createTables(db);
  
  // Seed with test data
  seedDatabase(db);
  
  return db;
}
