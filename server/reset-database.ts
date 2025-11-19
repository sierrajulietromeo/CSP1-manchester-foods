#!/usr/bin/env tsx

/**
 * Database Reset Script for Manchester Fresh Foods
 * 
 * This script deletes the existing database.sqlite file and reinitializes
 * a fresh database with all seed data. Useful for resetting between
 * penetration testing sessions.
 * 
 * Usage: npm run reset-db
 */

import { unlinkSync, existsSync } from "fs";
import { join } from "path";
import { initializeDatabase } from "./database";

const DB_PATH = join(process.cwd(), "database.sqlite");

console.log("🔄 Resetting Manchester Fresh Foods Database...\n");

// Delete existing database if it exists
if (existsSync(DB_PATH)) {
  console.log("🗑️  Deleting existing database...");
  unlinkSync(DB_PATH);
  console.log("✅ Database deleted\n");
} else {
  console.log("ℹ️  No existing database found\n");
}

// Initialize fresh database with seed data
console.log("🌱 Creating fresh database with seed data...");
const db = initializeDatabase();

console.log("✅ Database reset complete!\n");
console.log("📊 Database populated with:");
console.log("   - 6 customer accounts (thepubco, bella_italia, etc.)");
console.log("   - 1 admin account (admin / admin123)");
console.log("   - 20 fresh produce products");
console.log("   - Historical orders and reviews");
console.log("\n🎓 Ready for penetration testing!\n");

db.close();
