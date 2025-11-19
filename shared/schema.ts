import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, decimal, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Users table - customers and admin
export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(), // VULNERABILITY: Will store plaintext
  email: text("email").notNull(),
  companyName: text("company_name"),
  contactPerson: text("contact_person"),
  phone: text("phone"),
  address: text("address"),
  role: text("role").notNull().default("customer"), // customer or admin
  bio: text("bio"), // VULNERABILITY: XSS target
});

// Products table - fresh produce items
export const products = pgTable("products", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  description: text("description"),
  category: text("category").notNull(), // vegetables, fruits, herbs, dairy
  unit: text("unit").notNull(), // kg, box, bunch
  pricePerUnit: decimal("price_per_unit", { precision: 10, scale: 2 }).notNull(),
  imageUrl: text("image_url"),
  stock: integer("stock").notNull().default(100),
});

// Orders table
export const orders = pgTable("orders", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  orderNumber: text("order_number").notNull().unique(),
  status: text("status").notNull().default("pending"), // pending, confirmed, delivered, cancelled
  totalAmount: decimal("total_amount", { precision: 10, scale: 2 }).notNull(),
  deliveryDate: text("delivery_date"),
  deliveryAddress: text("delivery_address"),
  notes: text("notes"), // VULNERABILITY: XSS target
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
});

// Order items table
export const orderItems = pgTable("order_items", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orderId: varchar("order_id").notNull(),
  productId: varchar("product_id").notNull(),
  productName: text("product_name").notNull(),
  quantity: integer("quantity").notNull(),
  pricePerUnit: decimal("price_per_unit", { precision: 10, scale: 2 }).notNull(),
  subtotal: decimal("subtotal", { precision: 10, scale: 2 }).notNull(),
});

// Reviews/Comments table - VULNERABILITY: XSS targets
export const reviews = pgTable("reviews", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  productId: varchar("product_id").notNull(),
  userId: varchar("user_id").notNull(),
  username: text("username").notNull(),
  rating: integer("rating").notNull(),
  comment: text("comment"), // VULNERABILITY: XSS target
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
});

// Contact form submissions - VULNERABILITY: XSS target
export const contactSubmissions = pgTable("contact_submissions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  email: text("email").notNull(),
  company: text("company"),
  message: text("message").notNull(), // VULNERABILITY: XSS target
  createdAt: timestamp("created_at").notNull().default(sql`now()`),
});

// Zod schemas for validation (intentionally weak for educational purposes)
export const insertUserSchema = createInsertSchema(users).omit({ id: true, role: true }).extend({
  password: z.string().min(1), // VULNERABILITY: No password strength requirements
});

export const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

export const insertProductSchema = createInsertSchema(products).omit({ id: true });

export const insertOrderSchema = createInsertSchema(orders).omit({ 
  id: true, 
  orderNumber: true, 
  createdAt: true 
});

export const insertOrderItemSchema = createInsertSchema(orderItems).omit({ id: true });

export const insertReviewSchema = createInsertSchema(reviews).omit({ 
  id: true, 
  createdAt: true,
  username: true 
});

export const insertContactSchema = createInsertSchema(contactSubmissions).omit({ 
  id: true, 
  createdAt: true 
});

// TypeScript types
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Product = typeof products.$inferSelect;
export type InsertProduct = z.infer<typeof insertProductSchema>;
export type Order = typeof orders.$inferSelect;
export type InsertOrder = z.infer<typeof insertOrderSchema>;
export type OrderItem = typeof orderItems.$inferSelect;
export type InsertOrderItem = z.infer<typeof insertOrderItemSchema>;
export type Review = typeof reviews.$inferSelect;
export type InsertReview = z.infer<typeof insertReviewSchema>;
export type ContactSubmission = typeof contactSubmissions.$inferSelect;
export type InsertContact = z.infer<typeof insertContactSchema>;
