import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Shield, AlertTriangle, Code, Terminal } from "lucide-react";
import { useState } from "react";

const INSTRUCTOR_PASSWORD = "instructor2024";

export default function InstructorDocs() {
  const [password, setPassword] = useState("");
  const [authenticated, setAuthenticated] = useState(false);

  const handleAuth = () => {
    if (password === INSTRUCTOR_PASSWORD) {
      setAuthenticated(true);
    } else {
      alert("Incorrect password");
    }
  };

  if (!authenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center py-12 px-6 bg-muted/30">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Instructor Documentation</CardTitle>
            <CardDescription>Password-protected access for course instructors</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Enter Password</label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && handleAuth()}
                placeholder="Instructor password"
                data-testid="input-instructor-password"
              />
            </div>
            <Button onClick={handleAuth} className="w-full" data-testid="button-instructor-login">
              Access Documentation
            </Button>
            <p className="text-xs text-muted-foreground text-center">
              Hint: instructor2024
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen py-12 bg-background">
      <div className="max-w-5xl mx-auto px-6">
        <div className="mb-12">
          <Badge variant="destructive" className="mb-4">INSTRUCTOR ONLY</Badge>
          <h1 className="text-4xl font-semibold text-foreground mb-4">
            Manchester Fresh Foods - Vulnerability Guide
          </h1>
          <p className="text-lg text-muted-foreground">
            Educational penetration testing platform with 15 intentional security vulnerabilities
          </p>
        </div>

        <Alert className="mb-8">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            <strong>Important:</strong> This application contains deliberate security vulnerabilities for educational purposes only. 
            Never deploy this to production or expose it to the public internet.
          </AlertDescription>
        </Alert>

        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Recommended Testing Tools</CardTitle>
            <CardDescription>Essential tools for discovering vulnerabilities</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-2 gap-4">
              <div className="p-4 border border-border rounded-md">
                <h3 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  Burp Suite Community
                </h3>
                <p className="text-sm text-muted-foreground">
                  Web proxy for intercepting and modifying HTTP requests, essential for CSRF, XSS, and SQLi testing
                </p>
              </div>
              <div className="p-4 border border-border rounded-md">
                <h3 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  OWASP ZAP
                </h3>
                <p className="text-sm text-muted-foreground">
                  Free alternative to Burp Suite, automated scanner for finding vulnerabilities
                </p>
              </div>
              <div className="p-4 border border-border rounded-md">
                <h3 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  SQLmap
                </h3>
                <p className="text-sm text-muted-foreground">
                  Automated SQL injection detection and exploitation tool
                </p>
              </div>
              <div className="p-4 border border-border rounded-md">
                <h3 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  Browser DevTools
                </h3>
                <p className="text-sm text-muted-foreground">
                  Built-in browser tools for inspecting client-side code, local storage, and network requests
                </p>
              </div>
              <div className="p-4 border border-border rounded-md">
                <h3 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  Nikto
                </h3>
                <p className="text-sm text-muted-foreground">
                  Web server scanner for finding exposed files and security misconfigurations
                </p>
              </div>
              <div className="p-4 border border-border rounded-md">
                <h3 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  curl / Postman
                </h3>
                <p className="text-sm text-muted-foreground">
                  Testing API endpoints, authentication flows, and CSRF vulnerabilities
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <h2 className="text-2xl font-semibold text-foreground flex items-center gap-2">
            <Shield className="w-6 h-6" />
            All 15 Vulnerabilities
          </h2>

          <Accordion type="multiple" className="space-y-4">
            <AccordionItem value="vuln-1">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">CRITICAL</Badge>
                  <span className="font-semibold">1. SQL Injection in Login Form</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  The login endpoint constructs SQL queries using string concatenation without parameterization.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Location: /api/login</p>
                  <p className="font-mono text-sm mt-2">Test: Try username: admin' OR '1'='1</p>
                  <p className="font-mono text-sm">Password: anything</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Burp Suite, SQLmap</p>
                <p className="text-sm"><strong>Impact:</strong> Authentication bypass, data extraction</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-2">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">CRITICAL</Badge>
                  <span className="font-semibold">2. SQL Injection in Search/Order Tracking</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Product search and order tracking endpoints are vulnerable to SQL injection.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Location: /api/products (search parameter)</p>
                  <p className="font-mono text-sm">Test: ?search=' UNION SELECT * FROM users--</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> SQLmap, manual testing</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-3">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">HIGH</Badge>
                  <span className="font-semibold">3. Stored XSS in User Profile & Comments</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  User bio, order notes, and review comments are not sanitized and rendered without escaping.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Location: Profile bio, order notes, contact form</p>
                  <p className="font-mono text-sm">Test: {"<script>alert('XSS')</script>"}</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Browser, Burp Suite</p>
                <p className="text-sm"><strong>Impact:</strong> Session hijacking, credential theft</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-4">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">CRITICAL</Badge>
                  <span className="font-semibold">4. Plaintext Password Storage</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Passwords are stored in plaintext in the database without hashing.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Discovery: Extract database via SQLi or access user data</p>
                  <p className="font-mono text-sm">Impact: All user credentials immediately compromised</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Database access via SQLi</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-5">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">HIGH</Badge>
                  <span className="font-semibold">5. Weak Password Policy</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  No password complexity requirements - accepts single character passwords.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Test: Register with password "1" or "a"</p>
                  <p className="font-mono text-sm">No length, complexity, or common password checks</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Manual registration testing</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-6">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">HIGH</Badge>
                  <span className="font-semibold">6. Insecure Direct Object Reference (IDOR)</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Users can access other users' orders, invoices, and profiles by manipulating IDs.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Location: /api/orders/:id, /api/user/:id</p>
                  <p className="font-mono text-sm">Test: Change order ID in URL to view others' orders</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Burp Suite, browser</p>
                <p className="text-sm"><strong>Impact:</strong> Unauthorized data access</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-7">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">HIGH</Badge>
                  <span className="font-semibold">7. Missing CSRF Protection</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  State-changing operations (place order, update profile, change password) lack CSRF tokens.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Test: Create malicious HTML form that submits to /api/orders</p>
                  <p className="font-mono text-sm">Victim clicks link while logged in = unauthorized action</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Custom HTML, Burp Suite</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-8">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge>MEDIUM</Badge>
                  <span className="font-semibold">8. Verbose Error Messages</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Error responses reveal internal system details, database structure, and file paths.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Test: Send malformed requests to trigger detailed stack traces</p>
                  <p className="font-mono text-sm">Reveals: Technology stack, file paths, database schema</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Burp Suite, curl</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-9">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">CRITICAL</Badge>
                  <span className="font-semibold">9. Default Admin Credentials</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Default administrator account with easily guessable credentials exists.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Username: admin</p>
                  <p className="font-mono text-sm">Password: admin123</p>
                  <p className="font-mono text-sm mt-2">Accessible from login page</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Manual testing, credential stuffing tools</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-10">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge>MEDIUM</Badge>
                  <span className="font-semibold">10. No Rate Limiting</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Login endpoint and API routes have no rate limiting - enables brute force attacks.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Test: Automated login attempts with common passwords</p>
                  <p className="font-mono text-sm">No lockout mechanism or IP throttling</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Hydra, Burp Intruder, custom scripts</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-11">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge>MEDIUM</Badge>
                  <span className="font-semibold">11. Exposed API Keys in Client Code</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Sensitive configuration and commented-out API keys visible in JavaScript source.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Location: View page source, inspect bundled JavaScript</p>
                  <p className="font-mono text-sm">Look for: Commented credentials, debug keys</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Browser DevTools, source inspection</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-12">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">HIGH</Badge>
                  <span className="font-semibold">12. Server-Side Request Forgery (SSRF)</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Document fetching endpoint allows fetching arbitrary URLs without validation.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Location: POST /api/fetch-document</p>
                  <p className="font-mono text-sm">Test: {"url: \"http://localhost:5000/api/config\""}</p>
                  <p className="font-mono text-sm">Can fetch internal resources and expose sensitive data</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Burp Suite, curl</p>
                <p className="text-sm"><strong>Impact:</strong> Internal network scanning, credential exposure</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-12b">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">HIGH</Badge>
                  <span className="font-semibold">13. Local File Inclusion (LFI)</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Document viewer endpoint vulnerable to path traversal attacks.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Location: GET /api/view-document?file=...</p>
                  <p className="font-mono text-sm">Test: file=../../../../etc/passwd</p>
                  <p className="font-mono text-sm">Can read arbitrary files from the server</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Browser, Burp Suite</p>
                <p className="text-sm"><strong>Impact:</strong> Source code disclosure, credential theft</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-12c">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge>MEDIUM</Badge>
                  <span className="font-semibold">14. XML External Entity (XXE) Injection</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Order import functionality processes XML without disabling external entities.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Location: POST /api/import-order</p>
                  <p className="font-mono text-sm">Test: Send malicious XML with external entity</p>
                  <p className="font-mono text-sm">{`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`}</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Burp Suite, custom payloads</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-12d">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge>MEDIUM</Badge>
                  <span className="font-semibold">15. Predictable Session Tokens</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Session identifiers use sequential counter plus timestamp, making them predictable.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Pattern: sess_1000_timestamp, sess_1001_timestamp, etc.</p>
                  <p className="font-mono text-sm">Test: Create multiple sessions, analyze cookie patterns</p>
                  <p className="font-mono text-sm">Predict other users' session IDs to hijack sessions</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Burp Sequencer, manual analysis</p>
                <p className="text-sm"><strong>Impact:</strong> Session hijacking, account takeover</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-13x">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge>LOW</Badge>
                  <span className="font-semibold">13. Missing Security Headers</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  No X-Frame-Options, CSP, X-Content-Type-Options, or HSTS headers.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Test: Inspect HTTP response headers</p>
                  <p className="font-mono text-sm">Missing: X-Frame-Options (clickjacking), CSP (XSS defense)</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Browser DevTools, securityheaders.com</p>
                <p className="text-sm"><strong>Impact:</strong> Clickjacking, reduced XSS protection</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-14x">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge variant="destructive">HIGH</Badge>
                  <span className="font-semibold">14. Exposed Customer PII & Financial Data</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Unprotected customer database backup file exposes sensitive personal and financial information.
                </p>
                <div className="bg-muted p-4 rounded-md space-y-2">
                  <p className="font-mono text-sm font-semibold">Critical Discovery:</p>
                  <p className="font-mono text-sm">GET /data/customers.txt</p>
                  <p className="font-mono text-sm">Hint: Check robots.txt for hidden paths</p>
                  <p className="font-mono text-sm mt-3">Exposed Information:</p>
                  <p className="font-mono text-sm">• 7 customer accounts with full contact details</p>
                  <p className="font-mono text-sm">• Manchester addresses, phone numbers, emails</p>
                  <p className="font-mono text-sm">• Current account balances (£0 to £3,876)</p>
                  <p className="font-mono text-sm">• Credit limits and payment history</p>
                  <p className="font-mono text-sm">• Admin credentials exposed</p>
                  <p className="font-mono text-sm">• Notes about overdue payments & credit holds</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Browser, curl, Nikto, dirb</p>
                <p className="text-sm"><strong>Impact:</strong> GDPR breach, identity theft, competitive intelligence exposure, financial fraud</p>
                <p className="text-sm"><strong>Other Files:</strong> /.git/HEAD, /api/config, /robots.txt also leak information</p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vuln-15x">
              <AccordionTrigger className="text-left">
                <div className="flex items-center gap-4">
                  <Badge>MEDIUM</Badge>
                  <span className="font-semibold">15. Insufficient Input Validation</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 text-base">
                <p className="text-muted-foreground">
                  Business logic flaws: negative quantities, unlimited order amounts, file upload bypasses.
                </p>
                <div className="bg-muted p-4 rounded-md">
                  <p className="font-mono text-sm">Test: Order -100 items (negative pricing)</p>
                  <p className="font-mono text-sm">Upload files with double extensions: shell.php.jpg</p>
                </div>
                <p className="text-sm"><strong>Tools:</strong> Burp Suite, manual testing</p>
                <p className="text-sm"><strong>Impact:</strong> Business logic abuse, potential RCE</p>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </div>

        <Card className="mt-12">
          <CardHeader>
            <CardTitle>Assessment Guidance</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-foreground">
              Students should be encouraged to:
            </p>
            <ul className="list-disc list-inside space-y-2 text-muted-foreground ml-4">
              <li>Document each vulnerability with screenshots and reproduction steps</li>
              <li>Assess the severity and potential impact of each finding</li>
              <li>Propose remediation strategies for each vulnerability</li>
              <li>Understand the OWASP Top 10 mapping for each issue</li>
              <li>Practice responsible disclosure principles</li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
