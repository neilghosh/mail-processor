# Security Review and Fixes

## Overview
This document describes the comprehensive security review performed on the PDF processing implementation and the fixes applied.

## Security Vulnerabilities Found and Fixed

### 1. CRITICAL: Shell Injection Vulnerabilities (FIXED)

**Location:** `src/utils/pdf.ts`

**Issue:** 
- Used `exec()` with string interpolation for qpdf commands
- Vulnerable to command injection through malicious filenames or passwords

**Fix Applied:**
- Replaced `exec()` with `execFile()` which doesn't use shell interpretation
- Pass arguments as array instead of interpolating strings
- Removed manual password escaping (no longer needed with execFile)

**Before:**
```typescript
await execPromise(`qpdf --decrypt --password='${escapedPassword}' '${pdfPath}' '${decryptedPath}'`);
```

**After:**
```typescript
await execFilePromise('qpdf', [
    '--decrypt',
    `--password=${password}`,
    pdfPath,
    decryptedPath
]);
```

### 2. HIGH: Path Traversal Vulnerabilities (FIXED)

**Location:** `src/utils/pdf.ts`

**Issue:**
- User-controlled filenames used directly in path construction
- No validation of final file paths
- Potential for writing files outside intended directory

**Fix Applied:**
- Added `sanitizeFilename()` function to remove path separators and dangerous characters
- Added `validateFilePath()` function to ensure paths stay within expected directory
- Limit filename length to 255 characters
- Set restrictive file permissions (0600 for files, 0700 for directories)

**Features:**
- Removes `/` and `\` characters
- Replaces `..` sequences
- Removes non-printable and special characters
- Falls back to 'document.pdf' if filename becomes empty
- Validates resolved paths against expected directory

### 3. MEDIUM: Sensitive Data Exposure in Logs (FIXED)

**Location:** `src/utils/pdf.ts`, `src/utils/gemini.ts`, `src/index.ts`

**Issue:**
- Passwords and keywords logged to console
- Error messages potentially exposing sensitive information
- Filenames and paths in logs could leak information

**Fix Applied:**
- Removed keyword logging from password matching
- Sanitized error messages to avoid exposing passwords
- Removed detailed file paths from success messages
- Generic error messages for Gemini failures

**Changes:**
- Removed `keyword` from log: `console.log('Found password match for subject')`
- Removed error details: `console.error('Decryption failed')` (no error.message)
- Removed filenames from Gemini logs

### 4. MEDIUM: Input Validation Improvements (FIXED)

**Location:** `src/utils/pdf.ts`, `src/utils/gemini.ts`, `src/index.ts`

**Issue:**
- Limited validation on file attachments
- Only size check, no content validation
- No filename length or character validation

**Fix Applied:**
- Added file size validation before saving (in addition to existing check)
- Added file existence checks before processing
- Sanitized filenames before use
- Added size limit check before Gemini upload (10MB)
- Validate files exist and are readable before operations

### 5. MEDIUM: Error Handling and Cleanup (FIXED)

**Location:** `src/index.ts`, `src/utils/pdf.ts`

**Issue:**
- Temporary files not cleaned up in error paths
- Cleanup function could delete files outside /tmp

**Fix Applied:**
- Wrapped PDF processing in try-finally block
- Always cleanup temp files even on errors
- Added validation in cleanup to only delete paths under /tmp
- Added error handling for file operations

**Changes:**
```typescript
try {
    // Process PDFs
} finally {
    // Always cleanup temp files, even on error
    cleanupTempFiles(tempDir);
}
```

### 6. MEDIUM: Gemini API Security Improvements (FIXED)

**Location:** `src/utils/gemini.ts`

**Issue:**
- No file size validation before upload
- Full file paths in display names
- Detailed error messages

**Fix Applied:**
- Added file existence and size validation before upload
- Use only basename for display names
- Generic error messages
- File size limit enforcement (10MB)

### 7. HIGH: Password Security (IMPROVED)

**Location:** `src/utils/pdf.ts`

**Issue:**
- Passwords stored in plaintext in environment variables
- Passwords exposed in command construction
- JSON parsing errors could crash application

**Fix Applied:**
- Removed password from error logs
- Used execFile to avoid shell exposure of password
- Added try-catch for JSON parsing
- Generic error messages

**Remaining Concerns:**
- Passwords still stored in environment variables (consider using Secret Manager)
- No password rotation mechanism
- No encryption of passwords at rest

**Recommendations:**
- Use Google Cloud Secret Manager for password storage
- Implement password rotation policy
- Consider using asymmetric encryption for PDF passwords

### 8. Dockerfile Security (FIXED)

**Location:** `Dockerfile`

**Issue:**
- Running as root user
- No permission restrictions

**Fix Applied:**
- Created non-root user (`nodeuser`)
- Set proper ownership of application files
- Created temp directory with restricted permissions
- Run container as non-root user

**Changes:**
```dockerfile
RUN groupadd -r nodeuser && useradd -r -g nodeuser nodeuser
RUN chown -R nodeuser:nodeuser /usr/src/app
USER nodeuser
```

### 9. Dependency Vulnerabilities (FIXED)

**Issue:**
- 2 npm vulnerabilities (brace-expansion, braces)

**Fix Applied:**
- Ran `npm audit fix` to update vulnerable packages
- All vulnerabilities resolved

## Security Best Practices Implemented

1. **Principle of Least Privilege**
   - Run as non-root user in Docker
   - Restrictive file permissions (0600, 0700)
   - Limited file access to /tmp directory only

2. **Input Validation**
   - Filename sanitization
   - Path validation
   - File size limits
   - File existence checks

3. **Defense in Depth**
   - Multiple layers of validation
   - Error handling at each layer
   - Cleanup even on errors

4. **Secure Coding**
   - Use execFile instead of exec
   - No string interpolation in commands
   - Proper error handling
   - Sanitized logging

5. **Information Disclosure Prevention**
   - Generic error messages
   - No sensitive data in logs
   - Limited file path exposure

## Remaining Security Considerations

### High Priority
1. **Secret Management**
   - Move from environment variables to Google Cloud Secret Manager
   - Implement secret rotation
   - Encrypt sensitive configuration

2. **Rate Limiting**
   - Add rate limiting for Gemini API calls
   - Implement request throttling
   - Add usage monitoring

### Medium Priority
3. **Content Validation**
   - Validate PDF content/structure
   - Check for malicious embedded content
   - Implement file type verification beyond MIME type

4. **Audit Logging**
   - Log security events
   - Track file processing
   - Monitor for suspicious patterns

### Low Priority
5. **Advanced Security Headers**
   - Content Security Policy
   - Additional HTTP security headers
   - CORS configuration review

## Testing Recommendations

1. **Security Testing**
   - Test path traversal prevention with malicious filenames
   - Test command injection attempts
   - Verify cleanup in error scenarios
   - Test file size limits

2. **Penetration Testing**
   - Test with various malicious PDF files
   - Attempt to bypass input validation
   - Test error handling paths

3. **Code Analysis**
   - Run static analysis tools (CodeQL)
   - Dependency scanning
   - Regular security audits

## Compliance Notes

- All changes maintain backward compatibility
- No breaking changes to API
- Enhanced security posture
- Follows OWASP security best practices

## Change Summary

**Files Modified:**
- `src/utils/pdf.ts` - Shell injection fixes, path traversal prevention, sanitized logging
- `src/utils/gemini.ts` - Input validation, sanitized logging, error handling
- `src/index.ts` - Improved error handling and cleanup
- `Dockerfile` - Non-root user, proper permissions
- `package-lock.json` - Updated dependencies

**New Functions:**
- `sanitizeFilename()` - Prevent path traversal
- `validateFilePath()` - Ensure paths stay in expected directory

**Security Improvements:**
- Replaced exec with execFile (command injection prevention)
- Added filename sanitization (path traversal prevention)
- Removed sensitive data from logs (information disclosure prevention)
- Added try-finally blocks (proper cleanup)
- Non-root Docker user (privilege reduction)
- Updated dependencies (vulnerability fixes)

## Verification

Run the following to verify the fixes:

```bash
# Build the application
npm run build

# Run security audit
npm audit

# Check for known vulnerabilities
npm audit --audit-level=moderate

# Build Docker image
docker build -t mail-processor .

# Verify non-root user
docker run --rm mail-processor id
```

## References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE-78: OS Command Injection
- CWE-22: Path Traversal
- CWE-532: Information Exposure Through Log Files
- Node.js Security Best Practices: https://nodejs.org/en/docs/guides/security/
