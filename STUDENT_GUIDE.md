# Manchester Fresh Foods - Student Testing Guide

## Quick Start for Students

This is a deliberately vulnerable B2B food delivery application created for **penetration testing education**. Your goal is to discover and document security vulnerabilities.

### ⚠️ Important
- This application is **ONLY for educational use** in controlled environments
- Never use these techniques on real systems without authorization
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
Insecure Direct Object Reference (IDOR) occurs when an application exposes direct references to internal objects (like database IDs) without proper authorization checks.

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
    return res.status(403).json({ error: "Unauthorized" });
  }
  
  res.json(order);
});
```

---

## Other Vulnerabilities to Explore

### 1. SQL Injection (Login Page)
**Test**: Try username `' OR '1'='1' --` with any password
**Impact**: Complete authentication bypass

### 2. Exposed Customer Data
**Test**: Navigate to `/data/customers.txt`
**Hint**: Check `/robots.txt` first
**Impact**: Full PII leak - names, addresses, phone numbers, account balances

### 3. Stored XSS
**Test**: Update your profile bio with `<script>alert('XSS')</script>`
**Impact**: Execute JavaScript in other users' browsers

### 4. No Rate Limiting
**Test**: Try 100 login attempts with different passwords
**Impact**: Enables brute force attacks

### 5. Predictable Session Tokens
**Test**: Login twice and compare session cookie values
**Pattern**: `sess_{counter}_{timestamp}`
**Impact**: Session hijacking

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
- Test real websites without authorization
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
