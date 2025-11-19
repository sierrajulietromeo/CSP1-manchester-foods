import Database from "better-sqlite3";
import { randomUUID } from "crypto";

export function initializeDatabase(dbPath: string = "database.sqlite"): Database.Database {
  const db = new Database(dbPath);
  
  // Enable foreign keys
  db.pragma("foreign_keys = ON");
  
  // Create tables with SQLite syntax
  createTables(db);
  
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
  
  return db;
}
