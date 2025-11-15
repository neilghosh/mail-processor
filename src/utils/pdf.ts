
import { gmail_v1 } from 'googleapis';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { execFile } from 'child_process';

const execFilePromise = promisify(execFile);

// Interfaces
export interface PdfAttachment {
    filename: string;
    mimeType: string;
    size: number;
    attachmentId: string;
}

export interface PdfProcessingResult {
    filename: string;
    size: number;
    decryptionStatus: 'success' | 'failed' | 'not_needed' | 'skipped';
    filePath?: string;
    error?: string;
}

/**
 * Sanitize filename to prevent path traversal attacks
 */
function sanitizeFilename(filename: string): string {
    // Remove any path separators and parent directory references
    let sanitized = filename.replace(/[\/\\]/g, '_');
    sanitized = sanitized.replace(/\.\./g, '__');
    
    // Remove any non-printable or dangerous characters
    sanitized = sanitized.replace(/[^\w\s.-]/g, '_');
    
    // Limit filename length to prevent issues
    if (sanitized.length > 255) {
        const ext = path.extname(sanitized);
        const base = path.basename(sanitized, ext);
        sanitized = base.substring(0, 255 - ext.length) + ext;
    }
    
    // Ensure filename is not empty after sanitization
    if (!sanitized || sanitized.trim() === '') {
        sanitized = 'document.pdf';
    }
    
    return sanitized;
}

/**
 * Validate that a file path is within the expected directory
 */
function validateFilePath(filePath: string, expectedDir: string): boolean {
    const resolvedPath = path.resolve(filePath);
    const resolvedDir = path.resolve(expectedDir);
    return resolvedPath.startsWith(resolvedDir);
}

/**
 * Download a PDF attachment from Gmail
 */
export async function downloadPdfAttachment(
    gmail: gmail_v1.Gmail,
    userId: string,
    messageId: string,
    attachmentId: string,
    filename: string
): Promise<string | null> {
    try {
        // Sanitize filename to prevent path traversal
        const sanitizedFilename = sanitizeFilename(filename);
        console.log(`      📥 Downloading ${sanitizedFilename}...`);
        
        // Get attachment data
        const attachment = await gmail.users.messages.attachments.get({
            userId,
            messageId,
            id: attachmentId
        });

        if (!attachment.data.data) {
            console.error(`      ❌ No data in attachment response`);
            return null;
        }

        // Decode base64 data (Gmail uses URL-safe base64)
        const data = Buffer.from(attachment.data.data, 'base64');

        // Validate file size (additional check before saving)
        if (data.length > 10 * 1024 * 1024) {
            console.error(`      ❌ File too large: ${Math.round(data.length / 1024 / 1024)}MB`);
            return null;
        }

        // Create directory structure
        const dir = path.join('/tmp/mail-attachments', userId, messageId);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        }

        // Save file with sanitized name
        const filePath = path.join(dir, sanitizedFilename);
        
        // Validate the final path is within expected directory
        if (!validateFilePath(filePath, dir)) {
            console.error(`      ❌ Invalid file path detected`);
            return null;
        }
        
        fs.writeFileSync(filePath, data, { mode: 0o600 });

        console.log(`      ✅ Downloaded successfully`);
        return filePath;
    } catch (error: any) {
        console.error(`      ❌ Failed to download attachment:`, error.message);
        return null;
    }
}

/**
 * Check if a PDF is password protected
 */
export async function isPasswordProtected(pdfPath: string): Promise<boolean> {
    try {
        // Validate file exists and is readable
        if (!fs.existsSync(pdfPath)) {
            throw new Error('File does not exist');
        }
        
        // Use execFile instead of exec to prevent command injection
        const { stdout, stderr } = await execFilePromise('qpdf', ['--check', pdfPath]);
        const output = stdout + stderr;
        
        // If qpdf reports encryption, the PDF is password protected
        return output.includes('encrypted') || output.includes('password');
    } catch (error: any) {
        // qpdf returns non-zero exit code for encrypted PDFs without password
        const output = (error.stdout || '') + (error.stderr || '');
        return output.includes('encrypted') || output.includes('password');
    }
}

/**
 * Decrypt a password-protected PDF using qpdf
 */
export async function decryptPdf(pdfPath: string, password: string): Promise<string | null> {
    try {
        // Validate input file exists
        if (!fs.existsSync(pdfPath)) {
            throw new Error('Source PDF does not exist');
        }
        
        const decryptedPath = pdfPath.replace('.pdf', '_decrypted.pdf');
        
        console.log(`      🔓 Attempting to decrypt PDF...`);
        
        // Use execFile instead of exec to prevent command injection
        // Pass password and paths as separate arguments to avoid shell interpretation
        await execFilePromise('qpdf', [
            '--decrypt',
            `--password=${password}`,
            pdfPath,
            decryptedPath
        ]);
        
        console.log(`      ✅ Successfully decrypted PDF`);
        return decryptedPath;
    } catch (error: any) {
        // Don't log the full error which might contain the password
        console.error(`      ❌ Decryption failed`);
        return null;
    }
}

/**
 * Get password for a PDF based on subject keyword matching
 */
export function getPasswordForSubject(subject: string): string | null {
    try {
        const passwordsJson = process.env.PDF_PASSWORDS;
        
        if (!passwordsJson) {
            return null;
        }

        const passwords: { [key: string]: string } = JSON.parse(passwordsJson);
        const subjectLower = subject.toLowerCase();

        // Find first matching keyword (case-insensitive substring)
        for (const [keyword, password] of Object.entries(passwords)) {
            if (subjectLower.includes(keyword.toLowerCase())) {
                // Don't log the actual keyword to avoid exposing password mapping strategy
                console.log(`      🔑 Found password match for subject`);
                return password;
            }
        }

        return null;
    } catch (error: any) {
        // Don't log detailed parsing errors which might expose sensitive info
        console.error(`      ⚠️  Error parsing PDF_PASSWORDS configuration`);
        return null;
    }
}

/**
 * Clean up temporary files after processing
 */
export function cleanupTempFiles(directoryPath: string): void {
    try {
        if (fs.existsSync(directoryPath)) {
            // Validate the path is in /tmp to prevent accidental deletion
            const resolvedPath = path.resolve(directoryPath);
            if (!resolvedPath.startsWith('/tmp/')) {
                console.error(`      ⚠️  Refusing to cleanup path outside /tmp: ${resolvedPath}`);
                return;
            }
            
            fs.rmSync(directoryPath, { recursive: true, force: true });
            console.log(`      🧹 Cleaned up temp files`);
        }
    } catch (error: any) {
        console.error(`      ⚠️  Failed to cleanup temp files:`, error.message);
    }
}

/**
 * Extract PDF attachments from email message
 */
export function extractPdfAttachments(message: gmail_v1.Schema$Message): PdfAttachment[] {
    const pdfAttachments: PdfAttachment[] = [];
    
    const parts = message.payload?.parts || [];
    
    for (const part of parts) {
        if (part.mimeType === 'application/pdf' && part.body?.attachmentId) {
            pdfAttachments.push({
                filename: part.filename || 'unknown.pdf',
                mimeType: part.mimeType,
                size: part.body.size || 0,
                attachmentId: part.body.attachmentId
            });
        }
    }
    
    return pdfAttachments.slice(0, 5); // Limit to 5 PDFs max
}
