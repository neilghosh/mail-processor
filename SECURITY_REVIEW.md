# Security Review Report
## Mail Processor - PDF Processing Implementation

**Review Date:** 2025-11-15  
**Reviewer:** Security Audit Bot  
**Scope:** Comprehensive security audit of PDF processing and Gemini AI integration

---

## Executive Summary

This security review evaluated the mail-processor application focusing on PDF processing, command injection risks, credential management, and file handling. The review identified **7 security findings** ranging from High to Low severity.

**Critical Statistics:**
- **High Severity Issues:** 2
- **Medium Severity Issues:** 3
- **Low Severity Issues:** 2
- **Informational:** Multiple best practices recommendations

**Overall Risk Level:** 🟡 **MEDIUM** - Requires immediate attention for high-severity issues

---

## Detailed Findings

### 🔴 FINDING 1: Shell Command Injection Vulnerability (HIGH)

**File:** `src/utils/pdf.ts`  
**Lines:** 78, 103  
**Risk Level:** HIGH

**Description:**
The application uses shell command execution via `execPromise` with single-quote escaping for both `qpdf --check` and `qpdf --decrypt` commands. While the password is escaped using `replace(/'/g, "'\\''")`, the PDF file paths are wrapped in single quotes without proper validation.

**Vulnerable Code:**
```typescript
// Line 78 - isPasswordProtected()
const { stdout, stderr } = await execPromise(`qpdf --check '${pdfPath}' 2>&1`);

// Line 103 - decryptPdf()
await execPromise(`qpdf --decrypt --password='${escapedPassword}' '${pdfPath}' '${decryptedPath}'`);
```

**Attack Vector:**
If an attacker can control the filename (e.g., through email attachments), they could inject malicious commands:
- Filename: `test.pdf'; rm -rf /tmp/* #.pdf`
- Resulting command: `qpdf --check 'test.pdf'; rm -rf /tmp/* #.pdf'`

**Current Mitigation:**
The `downloadPdfAttachment` function (line 61) constructs paths using `path.join()`, which provides some protection. However, filenames from email attachments are user-controlled.

**Impact:**
- Remote code execution on the server
- Data loss or system compromise
- Potential lateral movement in the infrastructure

**Remediation:**

1. **Use Array-based Command Execution (Recommended):**
```typescript
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFilePromise = promisify(execFile);

// Safe version - no shell interpretation
export async function isPasswordProtected(pdfPath: string): Promise<boolean> {
    try {
        const { stdout, stderr } = await execFilePromise('qpdf', ['--check', pdfPath], {
            encoding: 'utf8',
            maxBuffer: 1024 * 1024 // 1MB
        });
        const output = stdout + stderr;
        return output.includes('encrypted') || output.includes('password');
    } catch (error: any) {
        const output = error.stdout + error.stderr;
        return output.includes('encrypted') || output.includes('password');
    }
}

export async function decryptPdf(pdfPath: string, password: string): Promise<string | null> {
    try {
        const decryptedPath = pdfPath.replace('.pdf', '_decrypted.pdf');
        console.log(`      🔓 Attempting to decrypt PDF...`);
        
        await execFilePromise('qpdf', [
            '--decrypt',
            `--password=${password}`,
            pdfPath,
            decryptedPath
        ], {
            maxBuffer: 10 * 1024 * 1024 // 10MB
        });
        
        console.log(`      ✅ Successfully decrypted PDF`);
        return decryptedPath;
    } catch (error: any) {
        console.error(`      ❌ Decryption failed:`, error.message);
        return null;
    }
}
```

2. **Validate Filenames:**
```typescript
function sanitizeFilename(filename: string): string {
    // Remove path traversal characters and dangerous characters
    return filename.replace(/[^a-zA-Z0-9._-]/g, '_');
}

// In downloadPdfAttachment
const sanitizedFilename = sanitizeFilename(filename);
const filePath = path.join(dir, sanitizedFilename);
```

3. **Set Timeouts:**
Add timeout protection to prevent resource exhaustion:
```typescript
const execFileWithTimeout = async (cmd: string, args: string[], timeout: number = 30000) => {
    return Promise.race([
        execFilePromise(cmd, args),
        new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Command timeout')), timeout)
        )
    ]);
};
```

**Priority:** 🔴 **CRITICAL** - Fix immediately before production deployment

---

### 🟡 FINDING 2: Path Traversal Vulnerability (MEDIUM)

**File:** `src/utils/pdf.ts`  
**Lines:** 55-62  
**Risk Level:** MEDIUM

**Description:**
The `downloadPdfAttachment` function constructs file paths using `path.join()` with user-controlled filenames from email attachments. While `path.join()` provides some protection, malicious filenames could still cause issues.

**Vulnerable Code:**
```typescript
const dir = path.join('/tmp/mail-attachments', userId, messageId);
if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
}
const filePath = path.join(dir, filename); // filename is user-controlled
fs.writeFileSync(filePath, data);
```

**Attack Vector:**
- Filename: `../../../etc/passwd`
- While `path.join` normalizes this, it could still write outside intended directory in edge cases

**Impact:**
- Arbitrary file write
- Potential overwrite of system files
- Directory traversal

**Remediation:**

1. **Validate and Sanitize Filenames:**
```typescript
function sanitizeFilename(filename: string): string {
    // Remove directory traversal sequences
    const basename = path.basename(filename);
    // Allow only alphanumeric, dots, dashes, and underscores
    const sanitized = basename.replace(/[^a-zA-Z0-9._-]/g, '_');
    // Ensure it ends with .pdf
    if (!sanitized.toLowerCase().endsWith('.pdf')) {
        return sanitized + '.pdf';
    }
    return sanitized;
}

// In downloadPdfAttachment
const sanitizedFilename = sanitizeFilename(filename);
const filePath = path.join(dir, sanitizedFilename);

// Verify the resolved path is still within the intended directory
const normalizedPath = path.normalize(filePath);
const normalizedDir = path.normalize(dir);
if (!normalizedPath.startsWith(normalizedDir)) {
    throw new Error('Invalid file path - potential path traversal');
}
```

2. **Implement File Size Validation:**
```typescript
// Already exists in index.ts (line 357) but should be in pdf.ts too
const MAX_PDF_SIZE = 10 * 1024 * 1024; // 10MB

if (data.length > MAX_PDF_SIZE) {
    throw new Error(`File too large: ${data.length} bytes`);
}
```

**Priority:** 🟡 **HIGH** - Address in next sprint

---

### 🟡 FINDING 3: Credential Exposure in Logs (MEDIUM)

**File:** `src/index.ts`, `src/utils/pdf.ts`  
**Lines:** Multiple  
**Risk Level:** MEDIUM

**Description:**
While the code has `sanitizeForLog()` function for email addresses, passwords and API keys may be exposed in error messages and logs.

**Vulnerable Areas:**

1. **PDF Password Logging (pdf.ts:130):**
```typescript
console.log(`      🔑 Found password match for keyword: ${keyword}`);
// This logs the keyword which might be sensitive
```

2. **Error Messages May Contain Sensitive Data:**
```typescript
// Line 107-109 in pdf.ts
console.error(`      ❌ Decryption failed:`, error.message);
// Error message might contain the password
```

3. **Gemini API Errors (gemini.ts:106):**
```typescript
console.error(`      ❌ Gemini analysis failed for ${filename}:`, error.message);
// Error might contain API key if authentication fails
```

**Impact:**
- Exposure of passwords in log files
- API keys leaked in error tracking systems
- Compliance violations (GDPR, PCI-DSS)

**Remediation:**

1. **Sanitize Error Messages:**
```typescript
function sanitizeError(error: any): string {
    if (!error) return 'Unknown error';
    
    let message = error.message || String(error);
    
    // Remove potential API keys (pattern: alphanumeric strings 20+ chars)
    message = message.replace(/[A-Za-z0-9_-]{20,}/g, '***API_KEY***');
    
    // Remove potential passwords
    message = message.replace(/password[=:]\s*\S+/gi, 'password=***');
    
    // Remove email addresses
    message = message.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '***@***');
    
    return message;
}

// Usage:
console.error(`      ❌ Decryption failed:`, sanitizeError(error));
```

2. **Avoid Logging Sensitive Keywords:**
```typescript
// Instead of logging the keyword, use a hash or generic message
console.log(`      🔑 Found password match for subject`);
```

3. **Use Structured Logging:**
```typescript
import * as winston from 'winston';

const logger = winston.createLogger({
    format: winston.format.combine(
        winston.format.json(),
        winston.format((info) => {
            // Redact sensitive fields
            if (info.password) info.password = '***';
            if (info.apiKey) info.apiKey = '***';
            return info;
        })()
    ),
    transports: [new winston.transports.Console()]
});
```

**Priority:** 🟡 **MEDIUM** - Implement in next release

---

### 🟡 FINDING 4: Missing Input Validation for PDF Attachments (MEDIUM)

**File:** `src/utils/pdf.ts`, `src/index.ts`  
**Lines:** 159-176, 346-366  
**Risk Level:** MEDIUM

**Description:**
PDF attachment validation is incomplete. While there's a size check (10MB) in `index.ts`, there's no validation for:
- File type verification (actual content vs. MIME type)
- PDF structure validation
- Malicious PDF detection
- Filename validation

**Current Validation:**
```typescript
// index.ts:357 - Only size check
if (attachment.size > 10 * 1024 * 1024) {
    console.log(`      ⏭️  Skipping ${attachment.filename} (too large...)`);
    continue;
}

// pdf.ts:159-176 - Only checks MIME type from email metadata
export function extractPdfAttachments(message: gmail_v1.Schema$Message): PdfAttachment[] {
    // ...
    if (part.mimeType === 'application/pdf' && part.body?.attachmentId) {
        // No actual file content validation
    }
}
```

**Missing Validations:**
1. **Magic Bytes Verification:** Verify PDF signature (`%PDF-`)
2. **File Extension Check:** Validate against MIME type
3. **Maximum Attachment Count:** Already limited to 5 (good!)
4. **Content Scanning:** No malware scanning

**Impact:**
- Processing of malicious PDFs
- Resource exhaustion
- Potential exploit of PDF parsing libraries

**Remediation:**

1. **Add PDF Magic Bytes Validation:**
```typescript
function isPdfFile(data: Buffer): boolean {
    // PDF files start with %PDF-
    const pdfHeader = Buffer.from('%PDF-');
    return data.slice(0, 5).equals(pdfHeader);
}

// In downloadPdfAttachment, after decoding:
const data = Buffer.from(attachment.data.data, 'base64');

if (!isPdfFile(data)) {
    console.error(`      ❌ Invalid PDF file: ${filename}`);
    return null;
}
```

2. **Validate Filename Extensions:**
```typescript
function isValidPdfFilename(filename: string): boolean {
    const ext = path.extname(filename).toLowerCase();
    return ext === '.pdf';
}
```

3. **Implement File Type Validation:**
```typescript
import * as fileType from 'file-type';

const type = await fileType.fromBuffer(data);
if (!type || type.mime !== 'application/pdf') {
    console.error(`      ❌ File type mismatch: ${filename}`);
    return null;
}
```

4. **Add Content Security Checks:**
```typescript
// Use qpdf to validate PDF structure before processing
async function validatePdfStructure(pdfPath: string): Promise<boolean> {
    try {
        await execFilePromise('qpdf', ['--check', pdfPath]);
        return true;
    } catch (error) {
        console.error('Invalid PDF structure');
        return false;
    }
}
```

**Priority:** 🟡 **MEDIUM** - Implement before handling untrusted PDFs

---

### 🟢 FINDING 5: Incomplete Resource Cleanup (LOW)

**File:** `src/index.ts`, `src/utils/pdf.ts`  
**Lines:** 145-154, 446  
**Risk Level:** LOW

**Description:**
The `cleanupTempFiles()` function is called after PDF processing, but there are edge cases where temp files might not be cleaned up:
1. Process crash before cleanup
2. Exception thrown before reaching cleanup code
3. Decrypted PDFs not cleaned up if original cleanup fails

**Current Implementation:**
```typescript
// pdf.ts:145
export function cleanupTempFiles(directoryPath: string): void {
    try {
        if (fs.existsSync(directoryPath)) {
            fs.rmSync(directoryPath, { recursive: true, force: true });
            console.log(`      🧹 Cleaned up temp files: ${directoryPath}`);
        }
    } catch (error: any) {
        console.error(`      ⚠️  Failed to cleanup ${directoryPath}:`, error.message);
    }
}

// index.ts:446 - Called after processing
cleanupTempFiles(tempDir);
```

**Missing Protection:**
- No try-finally blocks to guarantee cleanup
- No cleanup on process exit
- Decrypted files might persist if cleanup fails

**Impact:**
- Disk space exhaustion
- Sensitive data remaining on disk
- Potential information disclosure

**Remediation:**

1. **Use Try-Finally for Guaranteed Cleanup:**
```typescript
// In index.ts - process-emails route
const tempDir = `/tmp/mail-attachments/${user.google_id}/${message.id}`;
try {
    // Process PDFs...
    for (const attachment of pdfAttachments) {
        // ... processing code
    }
    
    // Gemini analysis...
} finally {
    // Always cleanup, even if processing fails
    cleanupTempFiles(tempDir);
}
```

2. **Implement Process Exit Handler:**
```typescript
// In index.ts, add at startup:
const tempDirectories = new Set<string>();

process.on('SIGTERM', () => {
    console.log('Cleaning up temp files before exit...');
    tempDirectories.forEach(dir => {
        try {
            if (fs.existsSync(dir)) {
                fs.rmSync(dir, { recursive: true, force: true });
            }
        } catch (e) {
            console.error(`Failed to cleanup ${dir}`);
        }
    });
    process.exit(0);
});

// Track directories
tempDirectories.add(tempDir);
```

3. **Cleanup Individual Files:**
```typescript
export function cleanupPdfFiles(filePaths: string[]): void {
    for (const filePath of filePaths) {
        try {
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
                console.log(`      🗑️  Deleted: ${filePath}`);
            }
        } catch (error: any) {
            console.error(`      ⚠️  Failed to delete ${filePath}:`, error.message);
        }
    }
}
```

4. **Schedule Periodic Cleanup:**
```typescript
// Clean up old temp files on startup and periodically
function cleanupOldTempFiles() {
    const tempRoot = '/tmp/mail-attachments';
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    if (!fs.existsSync(tempRoot)) return;
    
    const now = Date.now();
    const users = fs.readdirSync(tempRoot);
    
    for (const userId of users) {
        const userDir = path.join(tempRoot, userId);
        const stat = fs.statSync(userDir);
        
        if (now - stat.mtimeMs > maxAge) {
            fs.rmSync(userDir, { recursive: true, force: true });
            console.log(`🧹 Cleaned up old temp directory: ${userDir}`);
        }
    }
}

// Run on startup and every hour
cleanupOldTempFiles();
setInterval(cleanupOldTempFiles, 60 * 60 * 1000);
```

**Priority:** 🟢 **LOW** - Nice to have, implement when time permits

---

### 🔴 FINDING 6: API Key Exposure Risk (HIGH)

**File:** `src/utils/gemini.ts`, `src/index.ts`  
**Lines:** 37-41, 65-69, 422  
**Risk Level:** HIGH

**Description:**
The GEMINI_API_KEY is accessed directly from environment variables without validation, and error messages might leak the API key. Additionally, there's no rate limiting or usage tracking.

**Vulnerable Code:**
```typescript
// gemini.ts:37
const apiKey = process.env.GEMINI_API_KEY;
if (!apiKey) {
    throw new Error('GEMINI_API_KEY environment variable is not set');
}

// Error handling that might leak API key
console.error(`      ❌ Gemini analysis failed for ${filename}:`, error.message);
```

**Risks:**
1. API key might appear in error messages if Google API returns authentication errors
2. No validation of API key format
3. No rate limiting on API calls
4. API key passed to GoogleAIFileManager without sanitization

**Impact:**
- API key exposure in logs
- Unauthorized usage if key is leaked
- Cost implications from API abuse
- Service disruption

**Remediation:**

1. **Validate API Key Format:**
```typescript
function validateGeminiApiKey(apiKey: string): boolean {
    // Gemini API keys typically start with 'AI' and have a specific length
    if (!apiKey || apiKey.length < 20) {
        return false;
    }
    // Add format validation based on Google's API key pattern
    return /^AI[a-zA-Z0-9_-]{35,}$/.test(apiKey);
}

export async function uploadFileToGemini(filePath: string, mimeType: string): Promise<string> {
    const apiKey = process.env.GEMINI_API_KEY;
    
    if (!apiKey || !validateGeminiApiKey(apiKey)) {
        throw new Error('Invalid or missing GEMINI_API_KEY');
    }
    // ...
}
```

2. **Sanitize Error Messages:**
```typescript
function sanitizeGeminiError(error: any): string {
    let message = error.message || String(error);
    
    // Remove API key if present (pattern match typical API keys)
    message = message.replace(/AI[a-zA-Z0-9_-]{35,}/g, '***API_KEY***');
    
    // Remove other sensitive patterns
    message = message.replace(/Bearer\s+[A-Za-z0-9._-]+/g, 'Bearer ***');
    message = message.replace(/token[=:]\s*\S+/gi, 'token=***');
    
    return message;
}

// Usage:
catch (error: any) {
    console.error(`      ❌ Gemini analysis failed:`, sanitizeGeminiError(error));
    throw new Error('Gemini analysis failed');
}
```

3. **Implement Rate Limiting:**
```typescript
class RateLimiter {
    private requests: number[] = [];
    private readonly maxRequests: number;
    private readonly windowMs: number;
    
    constructor(maxRequests: number = 60, windowMs: number = 60000) {
        this.maxRequests = maxRequests;
        this.windowMs = windowMs;
    }
    
    async checkLimit(): Promise<void> {
        const now = Date.now();
        this.requests = this.requests.filter(time => now - time < this.windowMs);
        
        if (this.requests.length >= this.maxRequests) {
            throw new Error('Rate limit exceeded for Gemini API');
        }
        
        this.requests.push(now);
    }
}

const geminiRateLimiter = new RateLimiter(60, 60000); // 60 requests per minute

export async function analyzePdfWithGemini(...): Promise<string> {
    await geminiRateLimiter.checkLimit();
    // ... rest of the code
}
```

4. **Secure API Key Storage:**
```typescript
// Check API key is not logged at startup
if (process.env.GEMINI_API_KEY) {
    console.log('✅ GEMINI_API_KEY is configured');
    // DON'T log the actual key
} else {
    console.warn('⚠️  GEMINI_API_KEY is not set - PDF analysis will be disabled');
}
```

**Priority:** 🔴 **CRITICAL** - Fix before production deployment

---

### 🟡 FINDING 7: Weak Password Storage (MEDIUM)

**File:** `src/utils/pdf.ts`, `.env.example`  
**Lines:** 116-140, PDF_PASSWORDS env var  
**Risk Level:** MEDIUM

**Description:**
PDF passwords are stored in plain text in the PDF_PASSWORDS environment variable as JSON. This creates several risks:
1. Passwords visible in environment variable listings
2. Passwords in plain text in .env files
3. No encryption for stored passwords
4. Passwords might be logged

**Current Implementation:**
```typescript
// .env.example:67
PDF_PASSWORDS='{"invoice":"password1","receipt":"password2"}'

// pdf.ts:118
const passwordsJson = process.env.PDF_PASSWORDS;
const passwords: { [key: string]: string } = JSON.parse(passwordsJson);
```

**Risks:**
- Environment variables visible to all processes
- Git repository might contain .env with real passwords
- Cloud Run/Docker logs might expose passwords
- No audit trail for password access

**Impact:**
- Unauthorized access to encrypted PDFs
- Compliance violations
- Data breach if passwords are leaked

**Remediation:**

1. **Encrypt Passwords in Environment:**
```typescript
import { decrypt } from './crypto';

export function getPasswordForSubject(subject: string): string | null {
    try {
        const passwordsJson = process.env.PDF_PASSWORDS;
        
        if (!passwordsJson) {
            return null;
        }

        // Passwords are stored encrypted in format:
        // {"invoice":"<encrypted_password>","receipt":"<encrypted_password>"}
        const encryptedPasswords: { [key: string]: string } = JSON.parse(passwordsJson);
        const subjectLower = subject.toLowerCase();

        for (const [keyword, encryptedPassword] of Object.entries(encryptedPasswords)) {
            if (subjectLower.includes(keyword.toLowerCase())) {
                console.log(`      🔑 Found password match for subject`);
                // Decrypt the password
                const password = decrypt(encryptedPassword);
                return password;
            }
        }

        return null;
    } catch (error: any) {
        console.error(`      ⚠️  Error accessing PDF passwords`);
        return null;
    }
}
```

2. **Use Secret Manager:**
```typescript
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

async function getSecretPassword(keyword: string): Promise<string | null> {
    try {
        const client = new SecretManagerServiceClient();
        const projectId = process.env.GOOGLE_CLOUD_PROJECT;
        const secretName = `pdf-password-${keyword}`;
        
        const [version] = await client.accessSecretVersion({
            name: `projects/${projectId}/secrets/${secretName}/versions/latest`,
        });
        
        const password = version.payload?.data?.toString();
        return password || null;
    } catch (error) {
        return null;
    }
}
```

3. **Audit Password Access:**
```typescript
const passwordAccessLog: Array<{
    keyword: string;
    timestamp: Date;
    subject: string;
}> = [];

export function getPasswordForSubject(subject: string): string | null {
    // ... existing code ...
    
    for (const [keyword, password] of Object.entries(passwords)) {
        if (subjectLower.includes(keyword.toLowerCase())) {
            // Log access (without the actual password)
            passwordAccessLog.push({
                keyword,
                timestamp: new Date(),
                subject: subject.substring(0, 50) // Truncate for privacy
            });
            
            return password;
        }
    }
    // ...
}
```

4. **Environment Variable Best Practices:**
```bash
# In .env.example, provide clear guidance:
# ============================================
# PDF Processing Configuration
# ============================================
# PDF password map (JSON format with ENCRYPTED passwords)
# Use the encryption utility to encrypt passwords first:
# node -e "const {encrypt} = require('./dist/utils/crypto'); console.log(encrypt('mypassword'))"
# Example: {"invoice":"<encrypted>","receipt":"<encrypted>"}
PDF_PASSWORDS='{"invoice":"iv:hex:encrypted:hex","receipt":"iv:hex:encrypted:hex"}'
```

**Priority:** 🟡 **MEDIUM** - Implement before handling sensitive PDFs

---

## Additional Security Observations

### ✅ Good Security Practices Found:

1. **Token Encryption (crypto.ts):**
   - Uses AES-256-CBC for OAuth token storage
   - Random IV generation for each encryption
   - Proper key derivation with SHA-256

2. **Basic Security Headers (index.ts:27-32):**
   ```typescript
   res.setHeader('X-Content-Type-Options', 'nosniff');
   res.setHeader('X-Frame-Options', 'DENY');
   res.setHeader('X-XSS-Protection', '1; mode=block');
   ```

3. **HTML Escaping (index.ts:35-44):**
   - Function to escape HTML special characters
   - Used when rendering email data in HTML reports

4. **API Authentication (index.ts:109-129):**
   - Requires API_KEY for /api/tasks/process-emails endpoint
   - Checks Authorization header or x-api-key header

5. **Size Limits:**
   - PDF size limited to 10MB (index.ts:357)
   - Maximum 5 PDFs per email (pdf.ts:175)

6. **Proper Error Handling:**
   - Try-catch blocks around critical operations
   - Error logging without terminating the process

### 🔍 Additional Recommendations:

#### 1. **Implement Content Security Policy (CSP):**
```typescript
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});
```

#### 2. **Add Request Rate Limiting:**
```typescript
import rateLimit from 'express-rate-limit';

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP'
});

app.use('/api/', apiLimiter);
```

#### 3. **Implement Request Validation:**
```typescript
import { body, validationResult } from 'express-validator';

app.post('/api/tasks/process-emails',
    authenticateRequest,
    [
        // Add validation middleware
        body().custom((value, { req }) => {
            if (Object.keys(req.body).length > 0) {
                throw new Error('Request body should be empty');
            }
            return true;
        })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        // ... existing code
    }
);
```

#### 4. **Add Helmet for Enhanced Security:**
```typescript
import helmet from 'helmet';

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));
```

#### 5. **Secure Dockerfile:**
Current Dockerfile uses `node:18-slim` which is good, but could be improved:
```dockerfile
FROM node:18-slim as builder

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Production stage
FROM node:18-slim

# Create non-root user
RUN groupadd -r nodejs && useradd -r -g nodejs nodejs

# Install qpdf
RUN apt-get update && apt-get install -y qpdf && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copy built files
COPY --from=builder /usr/src/app/dist ./dist
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY package*.json ./
COPY public ./public

# Set ownership
RUN chown -R nodejs:nodejs /usr/src/app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node -e "require('http').get('http://localhost:8080/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

CMD ["node", "dist/index.js"]
```

#### 6. **Add Security Monitoring:**
```typescript
// Track security events
interface SecurityEvent {
    type: 'auth_failure' | 'invalid_file' | 'command_injection_attempt' | 'rate_limit_exceeded';
    timestamp: Date;
    details: any;
}

const securityEvents: SecurityEvent[] = [];

function logSecurityEvent(type: SecurityEvent['type'], details: any) {
    securityEvents.push({ type, timestamp: new Date(), details });
    
    // Alert if too many events
    const recentEvents = securityEvents.filter(
        e => Date.now() - e.timestamp.getTime() < 60000
    );
    
    if (recentEvents.length > 10) {
        console.error('🚨 SECURITY ALERT: Multiple security events detected');
        // Send alert to monitoring system
    }
}
```

---

## Environment Variables Security

### Current .env.example Analysis:

**✅ Good Practices:**
- Comments explaining each variable
- Example format provided
- Warnings about not using in production

**⚠️ Improvements Needed:**

1. **Add .env to .gitignore:**
```gitignore
# Environment variables
.env
.env.local
.env.*.local
*.env

# But keep the example
!.env.example
```

2. **Validate Critical Environment Variables on Startup:**
```typescript
// In index.ts, add at the top:
const requiredEnvVars = [
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'ENCRYPTION_KEY',
    'API_KEY'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:', missingVars.join(', '));
    process.exit(1);
}

// Validate encryption key length
if (process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY.length < 32) {
    console.error('❌ ENCRYPTION_KEY must be at least 32 characters');
    process.exit(1);
}
```

3. **Secure Environment Variable Handling:**
```typescript
// Don't log environment variables
console.log('Environment check:');
console.log('- GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? '✅ Set' : '❌ Not set');
console.log('- ENCRYPTION_KEY:', process.env.ENCRYPTION_KEY ? '✅ Set' : '❌ Not set');
console.log('- GEMINI_API_KEY:', process.env.GEMINI_API_KEY ? '✅ Set' : '❌ Not set');
// DON'T log actual values
```

---

## Dependency Security

**Current Dependencies Audit:**
```bash
npm audit
```

**Findings:**
The project should run `npm audit` regularly to check for known vulnerabilities.

**Recommendations:**

1. **Add to package.json scripts:**
```json
{
  "scripts": {
    "audit": "npm audit",
    "audit:fix": "npm audit fix",
    "check-updates": "npx npm-check-updates"
  }
}
```

2. **Set up Dependabot:**
Create `.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

3. **Add Pre-commit Hooks:**
```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "npm audit --audit-level=high"
    }
  }
}
```

---

## File Upload Security (Gemini API)

**File:** `src/utils/gemini.ts`  
**Function:** `uploadFileToGemini()`

**Current Implementation Review:**
```typescript
const uploadResult = await fileManager.uploadFile(filePath, {
    mimeType,
    displayName: filePath.split('/').pop() || 'document.pdf'
});
```

**Security Concerns:**
1. ✅ Uses official Google SDK (good)
2. ✅ MIME type is controlled
3. ⚠️ Display name derived from file path (could leak server paths)

**Recommendations:**

1. **Sanitize Display Name:**
```typescript
const uploadResult = await fileManager.uploadFile(filePath, {
    mimeType,
    displayName: sanitizeFilename(path.basename(filePath))
});
```

2. **Validate File Before Upload:**
```typescript
export async function uploadFileToGemini(filePath: string, mimeType: string): Promise<string> {
    // Validate file exists and is readable
    if (!fs.existsSync(filePath)) {
        throw new Error('File does not exist');
    }
    
    const stats = fs.statSync(filePath);
    if (stats.size === 0) {
        throw new Error('File is empty');
    }
    
    if (stats.size > 10 * 1024 * 1024) {
        throw new Error('File too large for upload');
    }
    
    // ... rest of code
}
```

3. **Handle Upload Errors Securely:**
```typescript
try {
    const uploadResult = await fileManager.uploadFile(filePath, {
        mimeType,
        displayName: path.basename(filePath)
    });
    
    console.log(`      ✅ File uploaded successfully`);
    // Don't log the full URI which might contain sensitive tokens
    
    return uploadResult.file.uri;
} catch (error: any) {
    console.error(`      ❌ File upload failed`);
    throw new Error('Failed to upload file to Gemini');
}
```

---

## Testing Recommendations

To validate these security fixes, implement the following tests:

### 1. **Command Injection Tests:**
```typescript
// test/security/command-injection.test.ts
describe('Command Injection Prevention', () => {
    it('should prevent command injection in filenames', async () => {
        const maliciousFilename = "test.pdf'; rm -rf /tmp/*; echo 'pwned.pdf";
        // Test that this doesn't execute arbitrary commands
    });
    
    it('should prevent command injection in passwords', async () => {
        const maliciousPassword = "pass'; cat /etc/passwd #";
        // Test that this doesn't execute arbitrary commands
    });
});
```

### 2. **Path Traversal Tests:**
```typescript
describe('Path Traversal Prevention', () => {
    it('should prevent directory traversal in filenames', () => {
        const filename = '../../../etc/passwd';
        const sanitized = sanitizeFilename(filename);
        expect(sanitized).not.toContain('..');
        expect(sanitized).not.toContain('/');
    });
});
```

### 3. **Input Validation Tests:**
```typescript
describe('PDF Validation', () => {
    it('should reject non-PDF files', async () => {
        const fakeData = Buffer.from('This is not a PDF');
        expect(isPdfFile(fakeData)).toBe(false);
    });
    
    it('should accept valid PDF files', async () => {
        const validPdf = Buffer.from('%PDF-1.4\n...');
        expect(isPdfFile(validPdf)).toBe(true);
    });
});
```

---

## Compliance Considerations

### GDPR Compliance:
- ✅ User consent via OAuth
- ⚠️ Data retention policy not defined
- ⚠️ No user data deletion mechanism
- ⚠️ Temp files might contain personal data

**Recommendations:**
1. Implement data retention policy
2. Add user data deletion endpoint
3. Ensure temp file cleanup within 24 hours
4. Add privacy policy

### PCI-DSS (if handling payment PDFs):
- ⚠️ Passwords in plain text
- ⚠️ No encryption at rest for temp files
- ✅ Encryption in transit (HTTPS)

**Recommendations:**
1. Encrypt temp files on disk
2. Use secure key management
3. Implement audit logging

---

## Summary & Action Plan

### Immediate Actions (Critical - Within 24 hours):

1. ✅ **Fix Command Injection (Finding 1)**
   - Replace `exec()` with `execFile()`
   - Validate and sanitize all filenames
   - Estimated effort: 2-3 hours

2. ✅ **Secure API Keys (Finding 6)**
   - Sanitize error messages
   - Implement API key validation
   - Add rate limiting
   - Estimated effort: 3-4 hours

### Short-term Actions (High Priority - Within 1 week):

3. ✅ **Path Traversal Protection (Finding 2)**
   - Implement filename sanitization
   - Add path validation
   - Estimated effort: 2 hours

4. ✅ **Credential Exposure (Finding 3)**
   - Implement log sanitization
   - Review all console.log statements
   - Estimated effort: 2-3 hours

5. ✅ **Input Validation (Finding 4)**
   - Add PDF magic bytes validation
   - Implement file type verification
   - Estimated effort: 3-4 hours

### Medium-term Actions (Medium Priority - Within 2 weeks):

6. ✅ **Password Security (Finding 7)**
   - Encrypt passwords in environment
   - Consider Secret Manager
   - Estimated effort: 4-5 hours

7. ✅ **Resource Cleanup (Finding 5)**
   - Implement try-finally blocks
   - Add process exit handlers
   - Scheduled cleanup
   - Estimated effort: 2-3 hours

### Long-term Improvements (Low Priority - Within 1 month):

8. Add comprehensive security testing
9. Implement security monitoring
10. Set up Dependabot
11. Add request rate limiting
12. Implement CSP headers
13. Security audit logging
14. Dockerfile hardening

---

## Risk Assessment Matrix

| Finding | Severity | Likelihood | Impact | Overall Risk |
|---------|----------|------------|--------|--------------|
| Command Injection | High | Medium | Critical | 🔴 HIGH |
| API Key Exposure | High | Medium | High | 🔴 HIGH |
| Path Traversal | Medium | Low | High | 🟡 MEDIUM |
| Credential Logging | Medium | Medium | Medium | 🟡 MEDIUM |
| Input Validation | Medium | Medium | Medium | 🟡 MEDIUM |
| Password Storage | Medium | Low | Medium | 🟡 MEDIUM |
| Resource Cleanup | Low | Low | Low | 🟢 LOW |

---

## Conclusion

The mail-processor application has a solid foundation with good security practices like token encryption and basic input validation. However, there are **critical vulnerabilities** in command execution and API key handling that must be addressed immediately before production deployment.

**Overall Security Score: 6.5/10**

With the recommended remediations, the security score could improve to **8.5/10**.

### Next Steps:

1. Review this report with the development team
2. Prioritize findings based on the action plan
3. Implement critical fixes (Findings 1 & 6) immediately
4. Schedule security re-review after fixes
5. Implement automated security testing in CI/CD pipeline

---

**Report End**

*For questions or clarifications about this security review, please contact the security team.*
