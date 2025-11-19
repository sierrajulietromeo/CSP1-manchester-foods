# Manchester Fresh Foods - Deliberately Vulnerable Web Application

## Project Overview

This is a deliberately vulnerable web application created for undergraduate cybersecurity penetration testing education. It simulates "Manchester Fresh Foods," a fictitious B2B fresh produce delivery company based in Manchester, UK.

**⚠️ CRITICAL WARNING**: This application contains intentional security vulnerabilities for educational purposes only. NEVER deploy this to production or expose it to the public internet. Use only in controlled, isolated educational environments.

## Purpose

The application is designed to teach students how to:
- Identify common web application security vulnerabilities
- Use penetration testing tools (Burp Suite, SQLmap, OWASP ZAP, etc.)
- Understand attack vectors and exploitation techniques
- Document security findings professionally
- Recommend appropriate remediation strategies

## Technical Stack

- **Frontend**: React 18, TypeScript, Tailwind CSS, Shadcn UI, Wouter (routing)
- **Backend**: Express.js, TypeScript, Node.js
- **Database**: SQLite (better-sqlite3) with intentionally vulnerable SQL queries
- **Session Management**: Express-session (deliberately insecure configuration)
- **Design**: Professional green logistics theme (circa 2018-2019 aesthetic)

## Project Structure

```
├── client/                           # React frontend
│   ├── src/
│   │   ├── pages/
│   │   │   ├── home.tsx             # Public homepage with hero section
│   │   │   ├── products.tsx         # Product catalogue (vulnerable search)
│   │   │   ├── contact.tsx          # Contact form (XSS vulnerable)
│   │   │   ├── login.tsx            # Login page (SQL injection)
│   │   │   ├── register.tsx         # Registration (weak validation)
│   │   │   ├── instructor-docs.tsx  # Password-protected vulnerability guide
│   │   │   └── dashboard/
│   │   │       ├── dashboard.tsx    # Main dashboard
│   │   │       ├── place-order.tsx  # Order placement form
│   │   │       ├── orders.tsx       # Order history (IDOR vulnerable)
│   │   │       ├── invoices.tsx     # Invoice viewer
│   │   │       └── profile.tsx      # Profile editor (XSS vulnerable)
│   │   ├── components/
│   │   │   ├── public-header.tsx    # Public site navigation
│   │   │   └── app-sidebar.tsx      # Dashboard sidebar
│   │   └── index.css                # Tailwind config with green theme
├── server/
│   ├── routes.ts                    # All API endpoints (intentionally vulnerable)
│   ├── storage.ts                   # SQLite storage with vulnerable SQL queries
│   ├── database.ts                  # SQLite database initialization and seed data
│   ├── reset-database.ts            # Utility script to reset database for testing
│   └── index.ts                     # Express server setup
├── shared/
│   └── schema.ts                    # Shared data models (Drizzle + Zod)
├── database.sqlite                  # SQLite database file (auto-created)
├── design_guidelines.md             # UI/UX design specifications
└── STUDENT_GUIDE.md                 # Educational guide with SQL injection examples
```

## 15 Intentional Security Vulnerabilities

### 1. SQL Injection (HIGH)
- **Location**: Login form, product search
- **Attack**: `' OR '1'='1' --` in username field
- **Impact**: Authentication bypass, data extraction

### 2. Stored Cross-Site Scripting (XSS) (HIGH)
- **Locations**: Profile bio, order notes, contact form submissions
- **Attack**: `<script>alert(document.cookie)</script>`
- **Impact**: Session hijacking, credential theft

### 3. Plaintext Password Storage (CRITICAL)
- **Location**: User authentication
- **Impact**: Passwords stored without hashing
- **Detection**: Check storage or verbose error messages

### 4. Weak Password Policy (MEDIUM)
- **Issue**: No complexity requirements, minimum length 1 character
- **Attack**: Register with password "a"
- **Impact**: Easy brute force attacks

### 5. Insecure Direct Object Reference (IDOR) (HIGH)
- **Locations**: `/api/orders/:id`, `/api/profile/:userId`
- **Attack**: Increment order ID to access other users' orders
- **Impact**: Unauthorized data access

### 6. Missing CSRF Protection (MEDIUM)
- **Locations**: All state-changing endpoints
- **Attack**: Forged requests from external sites
- **Impact**: Unauthorized actions on behalf of authenticated users

### 7. Verbose Error Messages (MEDIUM)
- **Location**: All error responses
- **Exposure**: Stack traces, SQL queries, internal paths
- **Impact**: Information disclosure aids attackers

### 8. Default/Hardcoded Credentials (CRITICAL)
- **Credentials**: admin / admin123
- **Location**: Pre-populated in system
- **Impact**: Immediate administrative access

### 9. No Rate Limiting (MEDIUM)
- **Locations**: Login, registration, all endpoints
- **Attack**: Brute force attacks, credential stuffing
- **Impact**: Account compromise, DoS

### 10. Exposed Secrets in Client Code (HIGH)
- **Location**: JavaScript source code
- **Exposure**: API keys, session secrets
- **Impact**: Credential compromise

### 11. Predictable Session Tokens (HIGH)
- **Pattern**: `sess_1000_timestamp`, `sess_1001_timestamp`, etc.
- **Attack**: Session enumeration and hijacking
- **Impact**: Account takeover

### 12. Server-Side Request Forgery (SSRF) (HIGH)
- **Endpoint**: `POST /api/fetch-document`
- **Attack**: `{"url": "http://localhost:5000/api/config"}`
- **Impact**: Internal resource access, credential exposure

### 13. Local File Inclusion (LFI) (HIGH)
- **Endpoint**: `GET /api/view-document?file=...`
- **Attack**: `file=../../../../etc/passwd`
- **Impact**: Source code disclosure, credential theft

### 14. XML External Entity (XXE) Injection (MEDIUM)
- **Endpoint**: `POST /api/import-order`
- **Attack**: Malicious XML with external entities
- **Impact**: File disclosure, SSRF

### 15. Information Disclosure (MEDIUM)
- **Endpoints**: `/.git/HEAD`, `/robots.txt`, `/api/config`
- **Exposure**: Source code, database credentials, hidden paths
- **Impact**: Reconnaissance for further attacks

## Key Features

### Public Pages
- **Homepage**: Hero section with company branding, service overview
- **Products**: Fresh produce catalogue with search functionality
- **Contact**: Contact form for customer enquiries

### Customer Portal (Authentication Required - Customers Only)
- **Dashboard**: Overview with recent orders and statistics
- **Place Order**: Multi-step order placement form (customers only - admins cannot access)
- **My Orders**: Order history and status tracking for the logged-in customer
- **Invoices**: Invoice viewing and download
- **My Profile**: User profile management (editable bio with XSS)

### Admin Portal (Authentication Required - Admin Only)
- **Dashboard**: System overview
- **All Orders**: Complete view of all customer orders with customer information
  - Shows customer company names and contact persons
  - Searchable by customer name, order number, or status
  - Admins **cannot** place orders (only view/manage)
- **Profile**: Admin profile management

### Instructor Documentation
- **Access**: `/instructor` route, password-protected
- **Password**: `penetration-test-2024`
- **Contents**: Complete list of all 15 vulnerabilities with:
  - Severity ratings (High/Medium/Low)
  - Exploitation techniques
  - Recommended testing tools
  - Attack payloads and examples
  - Expected impact assessments

## British English & Currency

All content uses:
- **British English spelling**: centre (not center), colour (not color), etc.
- **GBP Sterling**: All prices formatted as £X.XX
- **Manchester context**: References to Manchester locations and UK business practices

## Default Test Accounts

```
Admin Account (Management Portal - View All Orders, No Order Placement):
  Username: admin
  Password: admin123

Customer Accounts (Can Place Orders):
  Username: thepubco
  Password: welcome123
  Company: The Pub Company Ltd

  Username: bella_italia
  Password: pasta2024
  Company: Bella Italia Restaurant
```

## Testing Recommendations

### Recommended Tools
1. **Burp Suite Community** - HTTP proxy, scanner, intruder
2. **SQLmap** - Automated SQL injection detection and exploitation
3. **OWASP ZAP** - Free alternative to Burp Suite
4. **Browser DevTools** - Client-side code inspection
5. **Nikto** - Web server scanner
6. **curl** - Command-line HTTP testing

### Testing Workflow
1. Explore the application as a normal user
2. Map all available functionality and endpoints
3. Test each input field for injection vulnerabilities
4. Examine client-side source code for exposed secrets
5. Test authentication and authorization controls
6. Analyze session management mechanisms
7. Test for information disclosure
8. Document all findings with evidence

## Educational Guidelines

This application is designed for **controlled educational environments only**:

1. **Never deploy to production** or expose to the internet
2. Use in isolated lab environments or local development only
3. Students should document findings professionally
4. Emphasize ethical hacking principles and responsible disclosure
5. Compare vulnerable code with secure alternatives
6. Discuss real-world impact of each vulnerability type

## Development Notes

### Running the Application

```bash
# Install dependencies (automatically handled by Replit)
npm install

# Start the application
npm run dev
```

The application will run on port 5000 with:
- Frontend served via Vite
- Backend API on `/api/*` routes
- Session management with in-memory store
- SQLite database with seed data

### Design Aesthetic

The application uses a professional but dated (2018-2019 era) design to make vulnerabilities educationally believable:
- Material Design-inspired green logistics theme
- Clean, corporate B2B aesthetic
- Professional colour scheme: green primary, neutral grays
- Responsive design with mobile menu

### Storage Architecture

Uses SQLite database (`database.sqlite`) with intentionally vulnerable SQL queries:
- **Database**: SQLite file created automatically on first run
- **Seed Data**: Pre-populated with users, products, orders, reviews, and contact submissions
- **Vulnerable Queries**: String concatenation instead of parameterized queries for authentic SQL injection testing
- **Reset Utility**: Run `tsx server/reset-database.ts` to delete and reseed the database
- **Storage Interface**: `server/storage.ts` with `SQLiteStorage` class implementing all CRUD operations
- **Data Persistence**: Database persists across restarts (unlike in-memory storage)

## Security Remediation Examples

For instructors teaching remediation:

### SQL Injection → Parameterized Queries
```typescript
// VULNERABLE
const query = `SELECT * FROM users WHERE username='${username}'`;

// SECURE
const query = 'SELECT * FROM users WHERE username = ?';
db.execute(query, [username]);
```

### XSS → Output Encoding
```typescript
// VULNERABLE
bio.innerHTML = userBio;

// SECURE
bio.textContent = userBio; // React does this automatically
```

### Plaintext Passwords → Hashing
```typescript
// VULNERABLE
user.password = password;

// SECURE
import bcrypt from 'bcrypt';
user.password = await bcrypt.hash(password, 10);
```

### Predictable Sessions → Cryptographic Random
```typescript
// VULNERABLE
genid: () => `sess_${counter++}_${Date.now()}`

// SECURE
import { randomUUID } from 'crypto';
genid: () => randomUUID()
```

## License & Disclaimer

This application is provided for **educational purposes only**. The intentional security vulnerabilities are designed to teach students about web application security testing.

**NEVER** use this code in production environments or expose it to untrusted networks. The authors assume no responsibility for misuse of this educational material.

## Contact & Support

For questions about the educational content or vulnerability scenarios, consult the instructor documentation at `/instructor` (password: `penetration-test-2024`).
