# PDF Processing with Gemini AI - Implementation Plan

**Created**: 2025-11-15  
**Status**: Ready for Implementation  
**Feature**: Extract PDF attachments from emails, decrypt if needed, analyze with Gemini Flash, include insights in email reports

---

## Overview

Enhance the email processor to:
1. Extract PDF attachments from Gmail messages
2. Decrypt password-protected PDFs using qpdf
3. Send PDFs to Gemini Flash API for analysis
4. Include AI insights in the email report

---

## Implementation Assumptions

### **Confirmed Decisions**
- ✅ **File Type**: PDF only (skip other attachment types)
- ✅ **Decryption Tool**: qpdf
- ✅ **AI Model**: Gemini 1.5 Flash
- ✅ **Gemini Method**: Upload PDF files directly via File API
- ✅ **Subject Matching**: First keyword match only (case-insensitive substring)
- ✅ **No Match Behavior**: Skip Gemini analysis if subject doesn't match any keyword
- ✅ **Multiple PDFs**: Analyze all PDFs separately, combine results in email

### **Technical Assumptions**
1. **Password Matching**: Keyword-based from subject (case-insensitive substring match)
   - _Rationale_: Predictable, faster, avoids brute-force

2. **Combined Analysis**: Separate API calls per PDF, then concatenate responses
   - _Rationale_: Avoids file size/token limits, better error handling

3. **Missing Password**: Skip decryption, try to analyze PDF as-is
   - _Rationale_: Many PDFs aren't password-protected

4. **Report Format**: List files separately, show combined analysis
   - _Rationale_: Better transparency

5. **Partial Failure**: Analyze successful PDFs, skip failed ones
   - _Rationale_: Don't lose good data due to one file failure

6. **Cleanup Timing**: Clean up temp files after each email processed
   - _Rationale_: Minimize disk usage

7. **GCP Project**: Same as `GOOGLE_CLOUD_PROJECT_ID`
   - _Rationale_: Simplifies configuration

8. **Limits**:
   - Max PDF size: **10MB** per file
   - Max PDFs per email: **5** files
   - Gemini timeout: **30 seconds** per file
   - Skip non-PDF attachments silently

---

## Configuration

### **New Environment Variables**

Add to `.env`:
```bash
# Gemini API
GEMINI_API_KEY=your-gemini-api-key-here

# PDF Passwords (JSON map: subject-keyword -> password)
PDF_PASSWORDS='{"invoice":"pass123","receipt":"pass456","report":"pass789"}'
```

Add to `.env.example`:
```bash
# Gemini API Configuration
GEMINI_API_KEY=your-gemini-api-key

# PDF password map (JSON format)
PDF_PASSWORDS='{"invoice":"password1","receipt":"password2"}'
```

### **Subject → Prompt Mapping**

Hardcoded in `src/utils/gemini.ts`:
```typescript
const SUBJECT_TO_PROMPT_MAP: { [key: string]: string } = {
  'invoice': 'Extract invoice details including vendor name, invoice number, total amount, date, and line items.',
  'receipt': 'Summarize this receipt: merchant name, total amount, date, payment method, and items purchased.',
  'report': 'Analyze this report and provide key insights, findings, and recommendations.',
  'contract': 'Extract key contract terms: parties involved, effective dates, termination clauses, and primary obligations.',
  'statement': 'Summarize this statement: period, account details, transactions, and balances.'
};
```

---

## File Structure

```
src/
├── index.ts              # Modified - integrate PDF processing
└── utils/
    ├── crypto.ts         # Existing - token encryption
    ├── pdf.ts            # NEW - PDF operations
    └── gemini.ts         # NEW - Gemini API integration
```

---

## Implementation TODO List

### **Phase 1: Setup & Dependencies**

- [ ] **Task 1.1**: Install required npm packages
  ```bash
  npm install @google/generative-ai mime-types
  npm install --save-dev @types/mime-types
  ```

- [ ] **Task 1.2**: Update `.env.example` with new variables
  - Add `GEMINI_API_KEY`
  - Add `PDF_PASSWORDS` example

- [ ] **Task 1.3**: Verify qpdf is available
  ```bash
  # On macOS
  brew install qpdf
  
  # On Ubuntu/Debian
  apt-get install qpdf
  ```
  - Add to Dockerfile if needed

---

### **Phase 2: Create PDF Utility Module**

**File**: `src/utils/pdf.ts`

- [ ] **Task 2.1**: Create basic file structure
  ```typescript
  // Interface definitions
  // Helper functions
  // Export main functions
  ```

- [ ] **Task 2.2**: Implement `downloadPdfAttachment()`
  - Parameters: `gmail, userId, messageId, attachmentId, filename`
  - Download attachment data from Gmail API
  - Decode base64 data
  - Save to `/tmp/mail-attachments/{userId}/{messageId}/{filename}`
  - Return: file path or null on error

- [ ] **Task 2.3**: Implement `isPasswordProtected()`
  - Parameters: `pdfPath`
  - Execute: `qpdf --check ${pdfPath}` or try to open
  - Return: boolean

- [ ] **Task 2.4**: Implement `decryptPdf()`
  - Parameters: `pdfPath, password`
  - Execute: `qpdf --decrypt --password=${password} ${input} ${output}`
  - Return: decrypted file path or null on failure
  - Log errors appropriately

- [ ] **Task 2.5**: Implement `getPasswordForSubject()`
  - Parameters: `subject`
  - Parse `process.env.PDF_PASSWORDS` JSON
  - Match first keyword (case-insensitive substring)
  - Return: password or null

- [ ] **Task 2.6**: Implement `cleanupTempFiles()`
  - Parameters: `directoryPath`
  - Remove directory and all contents
  - Handle errors gracefully

- [ ] **Task 2.7**: Add TypeScript interfaces
  ```typescript
  interface PdfAttachment {
    filename: string;
    mimeType: string;
    size: number;
    attachmentId: string;
  }
  
  interface PdfProcessingResult {
    filename: string;
    size: number;
    decryptionStatus: 'success' | 'failed' | 'not_needed' | 'skipped';
    filePath?: string;
    error?: string;
  }
  ```

---

### **Phase 3: Create Gemini Utility Module**

**File**: `src/utils/gemini.ts`

- [ ] **Task 3.1**: Create basic file structure
  - Import `@google/generative-ai`
  - Define prompt map constant
  - Initialize Gemini client

- [ ] **Task 3.2**: Implement `getPromptForSubject()`
  - Parameters: `subject`
  - Match first keyword in `SUBJECT_TO_PROMPT_MAP` (case-insensitive)
  - Return: matched prompt or null

- [ ] **Task 3.3**: Implement `uploadFileToGemini()`
  - Parameters: `filePath, mimeType`
  - Use Gemini File API to upload PDF
  - Return: file URI or throw error
  - Handle timeouts and errors

- [ ] **Task 3.4**: Implement `analyzePdfWithGemini()`
  - Parameters: `filePath, prompt, filename`
  - Upload file to Gemini
  - Send prompt with file reference
  - Get response from Gemini Flash
  - Return: analysis text
  - Timeout: 30 seconds
  - Handle API errors gracefully

- [ ] **Task 3.5**: Implement `analyzeMultiplePdfs()`
  - Parameters: `pdfResults[], prompt`
  - Loop through each PDF file
  - Call `analyzePdfWithGemini()` for each
  - Concatenate responses
  - Return: combined analysis string
  - Skip files that failed decryption

- [ ] **Task 3.6**: Add error handling & logging
  - Log each Gemini API call
  - Log token usage if available
  - Handle rate limiting errors
  - Handle file size errors (>10MB)

---

### **Phase 4: Update Main Email Processor**

**File**: `src/index.ts`

- [ ] **Task 4.1**: Import new utilities
  ```typescript
  import { downloadPdfAttachment, decryptPdf, getPasswordForSubject, cleanupTempFiles } from './utils/pdf';
  import { getPromptForSubject, analyzeMultiplePdfs } from './utils/gemini';
  ```

- [ ] **Task 4.2**: Update `emailDetails` interface
  ```typescript
  interface EmailDetail {
    subject: string;
    from: string;
    timestamp: string;
    date: Date;
    pdfAttachments?: Array<{
      filename: string;
      size: number;
      decryptionStatus: string;
      error?: string;
    }>;
    geminiAnalysis?: string;
  }
  ```

- [ ] **Task 4.3**: Add PDF extraction logic in email loop
  - After fetching email details (around line 322)
  - Check `fullMessage.data.payload.parts` for attachments
  - Filter for `mimeType === 'application/pdf'`
  - Limit to first 5 PDFs
  - Extract: filename, attachmentId, size

- [ ] **Task 4.4**: Add PDF download & decryption logic
  - Create temp directory for this email
  - For each PDF attachment:
    - Download using `downloadPdfAttachment()`
    - Check if password-protected
    - Get password using `getPasswordForSubject(subject)`
    - Decrypt if password available
    - Track results in array

- [ ] **Task 4.5**: Add Gemini analysis logic
  - Check if subject matches any prompt keyword
  - If match found:
    - Get prompt using `getPromptForSubject()`
    - Call `analyzeMultiplePdfs()` with successful PDFs
    - Store result in `emailDetail.geminiAnalysis`
  - If no match, skip analysis

- [ ] **Task 4.6**: Add cleanup after processing each email
  - Call `cleanupTempFiles()` for email's temp directory
  - Handle cleanup errors gracefully

- [ ] **Task 4.7**: Update HTML email report template
  - Add section for PDF attachments (if any)
  - Show list of processed PDFs
  - Show decryption status per file
  - Show combined Gemini analysis (if available)
  - Example format:
    ```html
    <div style="margin-top: 20px; border-top: 2px solid #eee; padding-top: 15px;">
      <h3>📎 PDF Attachments Analyzed</h3>
      <ul>
        <li>invoice_march.pdf (1.2 MB) - Decrypted ✓</li>
        <li>receipt_001.pdf (0.5 MB) - No password needed ✓</li>
      </ul>
      <div style="background: #f0f8ff; padding: 15px; border-radius: 5px; margin-top: 10px;">
        <strong>🤖 AI Insights:</strong>
        <p>[Gemini analysis here]</p>
      </div>
    </div>
    ```

- [ ] **Task 4.8**: Update stats saved to Datastore
  - Add PDF attachment metadata to `EmailStat` entity
  - Include Gemini analysis results
  - Track success/failure counts

---

### **Phase 5: Error Handling & Logging**

- [ ] **Task 5.1**: Add PDF-specific error handling
  - Handle missing qpdf binary
  - Handle corrupt PDF files
  - Handle oversized PDFs (>10MB)
  - Handle network errors during download

- [ ] **Task 5.2**: Add Gemini-specific error handling
  - Handle API key missing/invalid
  - Handle rate limiting (429 errors)
  - Handle timeout errors
  - Handle quota exceeded errors

- [ ] **Task 5.3**: Update logging
  - Log PDF processing start/end per email
  - Log decryption attempts and results
  - Log Gemini API calls (sanitize file content)
  - Log cleanup operations

- [ ] **Task 5.4**: Add sanitization for sensitive data
  - Don't log PDF content
  - Don't log passwords in plain text
  - Sanitize file paths in logs

---

### **Phase 6: Testing & Validation**

- [ ] **Task 6.1**: Create test `.env` configuration
  - Add test `GEMINI_API_KEY`
  - Add test `PDF_PASSWORDS`

- [ ] **Task 6.2**: Manual testing checklist
  - [ ] Email with no attachments (existing behavior)
  - [ ] Email with non-PDF attachment (should skip)
  - [ ] Email with unencrypted PDF (should analyze)
  - [ ] Email with encrypted PDF + correct password (should decrypt & analyze)
  - [ ] Email with encrypted PDF + wrong password (should skip & log)
  - [ ] Email with multiple PDFs (should analyze all)
  - [ ] Email with subject matching prompt keyword (should analyze)
  - [ ] Email with subject not matching any keyword (should skip analysis)
  - [ ] Email with oversized PDF >10MB (should skip & log)
  - [ ] Email with 6 PDFs (should process only first 5)

- [ ] **Task 6.3**: Error scenario testing
  - [ ] Missing GEMINI_API_KEY (should fail gracefully)
  - [ ] Invalid GEMINI_API_KEY (should log error)
  - [ ] Missing qpdf binary (should log error)
  - [ ] Network timeout during Gemini API call
  - [ ] Gemini rate limit exceeded

- [ ] **Task 6.4**: Integration testing
  - [ ] Full flow: authenticate → receive test email with PDF → process
  - [ ] Verify email report contains PDF analysis
  - [ ] Verify Datastore saves PDF metadata
  - [ ] Verify temp files are cleaned up

---

### **Phase 7: Documentation & Deployment**

- [ ] **Task 7.1**: Update README.md
  - Add PDF processing feature description
  - Document new environment variables
  - Add qpdf installation instructions
  - Add Gemini API setup instructions

- [ ] **Task 7.2**: Update Dockerfile
  - Add qpdf installation
    ```dockerfile
    RUN apt-get update && apt-get install -y qpdf && rm -rf /var/lib/apt/lists/*
    ```

- [ ] **Task 7.3**: Update `deploy-cloud-run.sh`
  - Add GEMINI_API_KEY to deployment
  - Add PDF_PASSWORDS to deployment

- [ ] **Task 7.4**: Update `setup.sh`
  - Add prompts for GEMINI_API_KEY
  - Add prompts for PDF_PASSWORDS

- [ ] **Task 7.5**: Security review
  - [ ] No hardcoded credentials
  - [ ] Passwords encrypted in logs
  - [ ] Temp files cleaned up properly
  - [ ] Input validation for file paths
  - [ ] Gemini API key stored securely

---

## Data Structures

### **Email Detail with PDF Support**
```typescript
interface EmailDetail {
  subject: string;
  from: string;
  timestamp: string;
  date: Date;
  pdfAttachments?: Array<{
    filename: string;
    size: number;
    decryptionStatus: 'success' | 'failed' | 'not_needed' | 'skipped';
    error?: string;
  }>;
  geminiAnalysis?: string;
}
```

### **PDF Processing Result**
```typescript
interface PdfProcessingResult {
  filename: string;
  size: number;
  decryptionStatus: 'success' | 'failed' | 'not_needed' | 'skipped';
  filePath?: string;
  error?: string;
}
```

---

## Code Flow

```
POST /api/tasks/process-emails
  │
  ├─ For each user:
  │   │
  │   ├─ For each email:
  │   │   │
  │   │   ├─ Fetch email details (existing)
  │   │   │
  │   │   ├─ Extract PDF attachments (NEW)
  │   │   │   ├─ Filter mimeType === 'application/pdf'
  │   │   │   ├─ Limit to 5 PDFs max
  │   │   │   └─ Get: filename, attachmentId, size
  │   │   │
  │   │   ├─ Download PDFs (NEW)
  │   │   │   ├─ Create temp dir: /tmp/mail-attachments/{userId}/{messageId}/
  │   │   │   ├─ Download each PDF
  │   │   │   └─ Save to temp directory
  │   │   │
  │   │   ├─ Decrypt PDFs if needed (NEW)
  │   │   │   ├─ Check if password-protected
  │   │   │   ├─ Get password from subject keyword match
  │   │   │   ├─ Run qpdf --decrypt
  │   │   │   └─ Track success/failure
  │   │   │
  │   │   ├─ Analyze with Gemini (NEW)
  │   │   │   ├─ Get prompt from subject keyword match
  │   │   │   ├─ If no match → skip analysis
  │   │   │   ├─ For each successful PDF:
  │   │   │   │   ├─ Upload to Gemini
  │   │   │   │   ├─ Send prompt
  │   │   │   │   └─ Get response
  │   │   │   └─ Combine all responses
  │   │   │
  │   │   ├─ Cleanup temp files (NEW)
  │   │   │
  │   │   ├─ Build email details with PDF info (MODIFIED)
  │   │   │
  │   │   └─ Save stats to Datastore (MODIFIED)
  │   │
  │   └─ Send email report with PDF analysis (MODIFIED)
  │
  └─ Return results
```

---

## Dependencies to Add

```json
{
  "dependencies": {
    "@google/generative-ai": "^0.1.3",
    "mime-types": "^2.1.35"
  },
  "devDependencies": {
    "@types/mime-types": "^2.1.4"
  }
}
```

---

## Environment Variables Summary

```bash
# Existing
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_CLOUD_PROJECT_ID=
ENCRYPTION_KEY=
API_KEY=
REDIRECT_URI=

# New for PDF Processing
GEMINI_API_KEY=your-gemini-api-key-here
PDF_PASSWORDS='{"invoice":"pass123","receipt":"pass456","report":"pass789"}'
```

---

## Next Session Checklist

When continuing this implementation:

1. ✅ Review this document
2. ✅ Check current progress (mark completed tasks)
3. ✅ Start with next uncompleted phase
4. ✅ Update TODO checkboxes as you complete tasks
5. ✅ Add notes/issues encountered in a "Notes" section below

---

## Notes & Issues

_Add any notes, blockers, or issues discovered during implementation here:_

- 

---

## Completion Criteria

Feature is complete when:
- [ ] All TODO tasks checked off
- [ ] Manual testing checklist passed
- [ ] Email reports show PDF analysis
- [ ] Deployment to Cloud Run successful
- [ ] Documentation updated
- [ ] Security review passed

---

**Last Updated**: 2025-11-15  
**Next Review**: _Mark date when you continue work_
