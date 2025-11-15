
import { gmail_v1 } from 'googleapis';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { exec } from 'child_process';

const execPromise = promisify(exec);

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
        console.log(`      📥 Downloading ${filename}...`);
        
        // Get attachment data
        const attachment = await gmail.users.messages.attachments.get({
            userId,
            messageId,
            id: attachmentId
        });

        if (!attachment.data.data) {
            console.error(`      ❌ No data in attachment response for ${filename}`);
            return null;
        }

        // Decode base64 data (Gmail uses URL-safe base64)
        const data = Buffer.from(attachment.data.data, 'base64');

        // Create directory structure
        const dir = path.join('/tmp/mail-attachments', userId, messageId);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        // Save file
        const filePath = path.join(dir, filename);
        fs.writeFileSync(filePath, data);

        console.log(`      ✅ Downloaded to ${filePath}`);
        return filePath;
    } catch (error: any) {
        console.error(`      ❌ Failed to download ${filename}:`, error.message);
        return null;
    }
}

/**
 * Check if a PDF is password protected
 */
export async function isPasswordProtected(pdfPath: string): Promise<boolean> {
    try {
        // Try to check the PDF with qpdf
        const { stdout, stderr } = await execPromise(`qpdf --check "${pdfPath}" 2>&1`);
        const output = stdout + stderr;
        
        // If qpdf reports encryption, the PDF is password protected
        return output.includes('encrypted') || output.includes('password');
    } catch (error: any) {
        // qpdf returns non-zero exit code for encrypted PDFs without password
        const output = error.stdout + error.stderr;
        return output.includes('encrypted') || output.includes('password');
    }
}

/**
 * Decrypt a password-protected PDF using qpdf
 */
export async function decryptPdf(pdfPath: string, password: string): Promise<string | null> {
    try {
        const decryptedPath = pdfPath.replace('.pdf', '_decrypted.pdf');
        
        console.log(`      🔓 Attempting to decrypt with provided password...`);
        
        // Use qpdf to decrypt
        await execPromise(`qpdf --decrypt --password="${password}" "${pdfPath}" "${decryptedPath}"`);
        
        console.log(`      ✅ Successfully decrypted to ${decryptedPath}`);
        return decryptedPath;
    } catch (error: any) {
        console.error(`      ❌ Decryption failed:`, error.message);
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
                console.log(`      🔑 Found password match for keyword: ${keyword}`);
                return password;
            }
        }

        return null;
    } catch (error: any) {
        console.error(`      ⚠️  Error parsing PDF_PASSWORDS:`, error.message);
        return null;
    }
}

/**
 * Clean up temporary files after processing
 */
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
