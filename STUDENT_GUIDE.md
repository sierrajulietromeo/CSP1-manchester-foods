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

#### Step 1: Login as First Customer
1. Navigate to `/login`
2. Login as **thepubco** / **welcome123**
3. Go to "My Orders" in the sidebar

#### Step 2: Note Your Orders
You'll see 3 orders:
- **MFF-1000** (Delivered)
- **MFF-1001** (Delivered)
- **MFF-1002** (Confirmed)

#### Step 3: Get Order Details
1. Open Browser DevTools (F12)
2. Go to the Network tab
3. Click on one of your orders
4. Observe the API request: `GET /api/orders/{order-id}`
5. Note the **order ID** (a UUID like `abc123-def456-...`)

#### Step 4: Logout and Login as Different Customer
1. Logout
2. Login as **bella_italia** / **pasta2024**
3. You'll see their orders (**MFF-1003**, **MFF-1004**, etc.)

#### Step 5: Access First Customer's Order
**Using Browser DevTools:**
1. Open Console tab
2. Run this JavaScript:
```javascript
fetch('/api/orders/{paste-thepubco-order-id-here}')
  .then(r => r.json())
  .then(console.log)
```

**Using Burp Suite:**
1. Intercept request to `/api/orders/{bella-order-id}`
2. Change the order ID to thepubco's order ID
3. Forward the request
4. Observe: You can view another customer's order!

**Using curl:**
```bash
# Get your session cookie first (from Browser DevTools > Application > Cookies)
curl -H "Cookie: connect.sid=your-session-cookie" \
  http://localhost:5000/api/orders/{thepubco-order-id}
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

## All 15 Vulnerabilities to Discover

This application contains 15 intentional security vulnerabilities organized by severity. Use this as a checklist for your penetration test.

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
**Locations**: Profile bio, order notes, contact form  
**Test payloads**:
- `<script>alert('XSS')</script>`
- `<script>alert(document.cookie)</script>`
- `<img src=x onerror=alert('XSS')>`
**Impact**: Session hijacking, credential theft, defacement  
**OWASP**: A03:2021 - Injection

#### 5. Insecure Direct Object Reference (IDOR)
**Locations**: `/api/orders/:id`, `/api/profile/:userId`  
**Test**: Login as one customer, capture order ID, login as different customer, access first customer's order ID  
**Tools**: Burp Suite Repeater, browser DevTools  
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
**Test payload**: `{"url": "http://localhost:5000/api/config"}`  
**Alternative targets**:
- `http://169.254.169.254/latest/meta-data/` (AWS metadata)
- `http://localhost:5000/data/customers.txt`
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

## Testing Tools Recommended

1. **Burp Suite Community** - HTTP interception and manipulation
2. **Browser DevTools** - Network inspection, JavaScript console
3. **SQLmap** - Automated SQL injection testing
4. **curl** - Command-line API testing
5. **Postman** - API endpoint testing

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

**Instructor Documentation**: Navigate to `/instructor` and enter password `instructor2024` for complete vulnerability details and testing hints.

**Stuck on a vulnerability?**: The instructor docs provide:
- All 15 vulnerability locations
- Specific testing techniques
- Tool recommendations
- Expected impacts
- Exploitation examples

---

Happy ethical hacking! 🛡️
