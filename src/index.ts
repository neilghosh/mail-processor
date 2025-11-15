
import express from 'express';
import { Datastore } from '@google-cloud/datastore';
import { google } from 'googleapis';
import { encrypt, decrypt } from './utils/crypto';
import { 
    downloadPdfAttachment, 
    decryptPdf, 
    getPasswordForSubject, 
    cleanupTempFiles, 
    extractPdfAttachments,
    isPasswordProtected,
    PdfProcessingResult 
} from './utils/pdf';
import { getPromptForSubject, analyzeMultiplePdfs } from './utils/gemini';
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 8080;

// Check for required environment variables
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    console.warn('Warning: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required for OAuth2 functionality');
}

// Add basic security middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

// Helper function to escape HTML special characters
function escapeHtml(text: string): string {
    const map: { [key: string]: string } = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, (m) => map[m]);
}

// Helper function to sanitize logs (remove sensitive data)
function sanitizeForLog(str: string): string {
    // Mask email addresses partially: user****@domain.com
    return str.replace(/([a-zA-Z0-9._%+-]{4})[a-zA-Z0-9._%+-]*(@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g, '$1****$2');
}

// Helper function to send email via Gmail API
async function sendEmailViaGmail(gmail: any, to: string, subject: string, htmlBody: string): Promise<boolean> {
    try {
        const message = [
            `To: ${to}`,
            'Content-Type: text/html; charset="UTF-8"',
            `Subject: ${subject}`,
            '',
            htmlBody
        ].join('\n');

        const encodedMessage = Buffer.from(message).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        await gmail.users.messages.send({
            userId: 'me',
            requestBody: {
                raw: encodedMessage
            }
        });

        console.log(`   📧 Email sent to ${to}`);
        return true;
    } catch (error: any) {
        const errorMessage = error?.message || String(error);
        console.error(`   ❌ Failed to send email: ${errorMessage}`);
        
        // Provide helpful guidance for common permission errors
        if (errorMessage.includes('Insufficient Permission')) {
            console.error(`   ⚠️  HINT: The gmail.send scope is required. User needs to re-authenticate.`);
        } else if (errorMessage.includes('Invalid Credentials')) {
            console.error(`   ⚠️  HINT: The token may have expired or become invalid. User needs to re-authenticate.`);
        }
        
        return false;
    }
}

// Trust the proxy to get the correct protocol (http vs https)
app.set('trust proxy', 1);

// Debug: Check if public folder exists
import { existsSync, readdirSync } from 'fs';
import { join } from 'path';
const publicPath = join(process.cwd(), 'public');
console.log(`[DEBUG] Current working directory: ${process.cwd()}`);
console.log(`[DEBUG] Public folder path: ${publicPath}`);
console.log(`[DEBUG] Public folder exists: ${existsSync(publicPath)}`);
if (existsSync(publicPath)) {
    console.log(`[DEBUG] Public folder contents: ${readdirSync(publicPath).join(', ')}`);
}

app.use(express.static('public'));

// Dynamic redirect URI based on environment
const redirectUri = process.env.REDIRECT_URI || `http://localhost:${port}/auth/google/callback`;

// Middleware to authenticate API requests (simple token-based auth)
function authenticateRequest(req: express.Request, res: express.Response, next: express.NextFunction) {
    // In production, use proper authentication (JWT, OAuth, etc)
    const authHeader = req.headers.authorization;
    
    // For now, require a simple token or X-API-Key header
    const apiKey = process.env.API_KEY || 'change-this-in-production';
    
    if (!authHeader && !req.headers['x-api-key']) {
        console.warn(`⚠️  Unauthorized access attempt to ${req.path}`);
        return res.status(401).json({ error: 'Unauthorized. Missing authentication.' });
    }
    
    const token = authHeader?.replace('Bearer ', '') || req.headers['x-api-key'];
    
    if (token !== apiKey) {
        console.warn(`⚠️  Invalid API key attempt to ${req.path}`);
        return res.status(403).json({ error: 'Forbidden. Invalid credentials.' });
    }
    
    next();
}

// Route to start the Google authentication flow
app.get('/auth/google', (req, res) => {
    const oauth2Client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        redirectUri
    );

    const scopes = [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.send',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
    ];

    const url = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: scopes,
        prompt: 'consent' // Force consent screen to get refresh token every time
    });

    res.redirect(url);
});

// The callback route that Google redirects to
app.get('/auth/google/callback', async (req, res) => {
    const oauth2Client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        redirectUri
    );

    const { code } = req.query; 

    try {
        const { tokens } = await oauth2Client.getToken(code as string);
        oauth2Client.setCredentials(tokens);

        const oauth2 = google.oauth2({
            auth: oauth2Client,
            version: 'v2'
        });

        const { data } = await oauth2.userinfo.get();

        console.log('OAuth tokens received:', {
            hasAccessToken: !!tokens.access_token,
            hasRefreshToken: !!tokens.refresh_token,
            tokenType: tokens.token_type,
            expiresIn: tokens.expiry_date
        });

        try {
            const datastore = new Datastore({
                projectId: process.env.GOOGLE_CLOUD_PROJECT || process.env.GOOGLE_CLOUD_PROJECT_ID
            });
            const kind = 'User';
            const userKey = datastore.key([kind, data.id!]);
            
            // If refresh token is missing, log warning
            if (!tokens.refresh_token) {
                console.warn(`⚠️  Warning: No refresh token received for user ${data.email}. This might be a re-authentication. Consider revoking previous tokens.`);
            }

            const user = {
                key: userKey,
                data: {
                    google_id: data.id,
                    email: data.email,
                    refreshToken: tokens.refresh_token ? encrypt(tokens.refresh_token) : null,
                    accessToken: tokens.access_token ? encrypt(tokens.access_token) : null,
                    tokenExpiry: tokens.expiry_date || null,
                    createdAt: new Date()
                }
            };

            await datastore.save(user);
            console.log(`✅ User ${data.email} successfully saved to Datastore`);
            res.send('Authentication successful! You can close this tab.');
        } catch (datastoreError) {
            console.error('Datastore error:', datastoreError);
            // For local development without Datastore credentials
            console.log('User authenticated:', data.email);
            res.send('Authentication successful! (Note: User data not saved - Datastore credentials not configured)');
        }
    } catch (error) {
        console.error('Error during Google auth callback:', error);
        res.status(500).send('Authentication failed. Please check the server logs for more details.');
    }
});

app.post('/api/tasks/process-emails', authenticateRequest, async (req, res) => {
    console.log('\n📧 ====== EMAIL PROCESSING STARTED ======');
    const startTime = Date.now();
    
    try {
        console.log('🔧 Initializing Datastore...');
        const datastore = new Datastore({
            projectId: process.env.GOOGLE_CLOUD_PROJECT || process.env.GOOGLE_CLOUD_PROJECT_ID
        });
        
        console.log('📋 Querying users from Datastore...');
        const query = datastore.createQuery('User');
        const [users] = await datastore.runQuery(query);
        
        console.log(`✅ Found ${users.length} users in database`);

        if (users.length === 0) {
            console.warn('⚠️  No users found in database. Please authenticate first.');
            return res.status(200).json({ 
                message: 'No users found', 
                processedUsers: 0,
                totalEmails: 0
            });
        }

        let processedUsers = 0;
        let totalEmails = 0;
        const results = [];

        for (const user of users) {
            console.log(`\n👤 Processing user: ${user.email || 'unknown'}`);
            
            try {
                const refreshToken = decrypt(user.refreshToken);
                const accessToken = decrypt(user.accessToken);
                
                console.log(`   - Has refresh token: ${!!refreshToken}`);
                console.log(`   - Has access token: ${!!accessToken}`);
                
                // Skip users without any valid token
                if (!refreshToken && !accessToken) {
                    console.warn(`   ⏭️  SKIPPED: No valid tokens available`);
                    results.push({
                        email: user.email,
                        status: 'skipped',
                        reason: 'no_tokens'
                    });
                    continue;
                }

                console.log('🔐 Creating OAuth2 client...');
                const oauth2Client = new google.auth.OAuth2(
                    process.env.GOOGLE_CLIENT_ID,
                    process.env.GOOGLE_CLIENT_SECRET
                );

                // Use refresh token if available, otherwise use access token
                if (refreshToken) {
                    console.log('   ↻ Using refresh token...');
                    oauth2Client.setCredentials({ refresh_token: refreshToken });
                    const { token } = await oauth2Client.getAccessToken();
                    oauth2Client.setCredentials({ access_token: token });
                    console.log('   ✅ Got new access token from refresh token');
                } else if (accessToken) {
                    console.log('   ⚠️  Using stored access token (no refresh token)');
                    oauth2Client.setCredentials({ access_token: accessToken });
                }

                console.log('📬 Fetching Gmail messages...');
                const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
                const dateFilter = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().substring(0, 10);
                
                const response = await gmail.users.messages.list({
                    userId: 'me',
                    q: `is:unread in:inbox after:${dateFilter}`
                });

                const newEmailCount = response.data.resultSizeEstimate || 0;
                console.log(`   📊 Found ${newEmailCount} unread emails from last 24 hours`);
                console.log(`   📩 Message IDs: ${(response.data.messages || []).map(m => m.id).join(', ') || 'none'}`);

                // Fetch detailed information for each message
                console.log('   📄 Fetching email details...');
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
                const emailDetails: EmailDetail[] = [];

                if (response.data.messages && response.data.messages.length > 0) {
                    for (const message of response.data.messages) {
                        try {
                            const fullMessage = await gmail.users.messages.get({
                                userId: 'me',
                                id: message.id!,
                                format: 'full'
                            });

                            const headers = fullMessage.data.payload?.headers || [];
                            const subject = headers.find((h: any) => h.name === 'Subject')?.value || '(No Subject)';
                            const from = headers.find((h: any) => h.name === 'From')?.value || 'Unknown Sender';
                            const date = headers.find((h: any) => h.name === 'Date')?.value || 'Unknown Date';
                            const internalDate = fullMessage.data.internalDate;
                            const messageDate = new Date(parseInt(internalDate as string || Date.now().toString()));

                            console.log(`     - ${subject} (from ${from})`);

                            const emailDetail: EmailDetail = {
                                subject,
                                from,
                                timestamp: date,
                                date: messageDate
                            };

                            // Extract PDF attachments
                            const pdfAttachments = extractPdfAttachments(fullMessage.data);
                            
                            if (pdfAttachments.length > 0) {
                                console.log(`      📎 Found ${pdfAttachments.length} PDF attachment(s)`);
                                
                                const pdfResults: PdfProcessingResult[] = [];
                                const tempDir = `/tmp/mail-attachments/${user.google_id}/${message.id}`;

                                try {
                                    // Process each PDF
                                    for (const attachment of pdfAttachments) {
                                        // Skip files larger than 10MB
                                        if (attachment.size > 10 * 1024 * 1024) {
                                            console.log(`      ⏭️  Skipping attachment (too large: ${Math.round(attachment.size / 1024 / 1024)}MB)`);
                                            pdfResults.push({
                                                filename: attachment.filename,
                                                size: attachment.size,
                                                decryptionStatus: 'skipped',
                                                error: 'File too large (>10MB)'
                                            });
                                            continue;
                                        }

                                        // Download PDF
                                        const pdfPath = await downloadPdfAttachment(
                                            gmail,
                                            'me',
                                            message.id!,
                                            attachment.attachmentId,
                                            attachment.filename
                                        );

                                        if (!pdfPath) {
                                            pdfResults.push({
                                                filename: attachment.filename,
                                                size: attachment.size,
                                                decryptionStatus: 'failed',
                                                error: 'Download failed'
                                            });
                                            continue;
                                        }

                                        // Check if password protected
                                        const isProtected = await isPasswordProtected(pdfPath);
                                        
                                        let finalPath = pdfPath;
                                        let decryptionStatus: 'success' | 'failed' | 'not_needed' | 'skipped' = 'not_needed';

                                        if (isProtected) {
                                            console.log(`      🔒 PDF is password protected`);
                                            const password = getPasswordForSubject(subject);
                                            
                                            if (password) {
                                                const decryptedPath = await decryptPdf(pdfPath, password);
                                                if (decryptedPath) {
                                                    finalPath = decryptedPath;
                                                    decryptionStatus = 'success';
                                                } else {
                                                    decryptionStatus = 'failed';
                                                }
                                            } else {
                                                console.log(`      ⚠️  No password configured for this subject`);
                                                decryptionStatus = 'skipped';
                                            }
                                        }

                                        pdfResults.push({
                                            filename: attachment.filename,
                                            size: attachment.size,
                                            decryptionStatus,
                                            filePath: decryptionStatus !== 'failed' ? finalPath : undefined
                                        });
                                    }

                                    // Analyze with Gemini if subject matches a prompt
                                    const prompt = getPromptForSubject(subject);
                                    
                                    if (prompt && process.env.GEMINI_API_KEY) {
                                        try {
                                            console.log(`      🤖 Analyzing PDFs with Gemini AI...`);
                                            const analysis = await analyzeMultiplePdfs(pdfResults, prompt);
                                            emailDetail.geminiAnalysis = analysis;
                                        } catch (geminiError: any) {
                                            console.error(`      ❌ Gemini analysis failed`);
                                            emailDetail.geminiAnalysis = `Analysis failed`;
                                        }
                                    } else if (!prompt) {
                                        console.log(`      ⏭️  No matching prompt for subject, skipping Gemini analysis`);
                                    } else {
                                        console.log(`      ⚠️  GEMINI_API_KEY not set, skipping analysis`);
                                    }

                                    // Add PDF attachment info to email detail
                                    emailDetail.pdfAttachments = pdfResults.map(pdf => ({
                                        filename: pdf.filename,
                                        size: pdf.size,
                                        decryptionStatus: pdf.decryptionStatus,
                                        error: pdf.error
                                    }));
                                } finally {
                                    // Always cleanup temp files, even on error
                                    cleanupTempFiles(tempDir);
                                }
                            }

                            emailDetails.push(emailDetail);
                        } catch (detailError) {
                            console.warn(`     - Failed to fetch details for message ${message.id}`);
                        }
                    }
                }

                console.log('�💾 Saving email stats to Datastore...');
                const emailStat = {
                    key: datastore.key('EmailStat'),
                    data: {
                        userId: user[datastore.KEY],
                        userEmail: user.email,
                        newEmailCount: newEmailCount,
                        processedAt: new Date(),
                        messageIds: (response.data.messages || []).map((m: any) => m.id),
                        emailDetails: emailDetails
                    }
                };

                await datastore.save(emailStat);
                console.log(`   ✅ Stats saved to Datastore`);

                // Send email report to user
                console.log('📧 Sending email report to user...');
                
                // Build email list HTML
                let emailListHTML = '';
                if (emailDetails.length > 0) {
                    emailListHTML = `
                        <div style="margin: 20px 0;">
                            <h3 style="color: #4285F4;">📬 Unread Emails:</h3>
                            <table style="width: 100%; border-collapse: collapse;">
                                <tr style="background-color: #e8f0fe; border-bottom: 2px solid #4285F4;">
                                    <th style="padding: 10px; text-align: left; color: #4285F4;">From</th>
                                    <th style="padding: 10px; text-align: left; color: #4285F4;">Subject</th>
                                    <th style="padding: 10px; text-align: left; color: #4285F4;">Date</th>
                                </tr>
                                ${emailDetails.map(email => {
                                    let rowHtml = `
                                        <tr style="border-bottom: 1px solid #ddd;">
                                            <td style="padding: 10px; font-size: 12px; word-break: break-word;">${escapeHtml(email.from)}</td>
                                            <td style="padding: 10px; font-size: 12px; font-weight: 500;">${escapeHtml(email.subject)}</td>
                                            <td style="padding: 10px; font-size: 12px; white-space: nowrap;">${email.date.toLocaleString()}</td>
                                        </tr>
                                    `;
                                    
                                    // Add PDF attachments row if present
                                    if (email.pdfAttachments && email.pdfAttachments.length > 0) {
                                        const statusIcon = (status: string) => {
                                            switch(status) {
                                                case 'success': return '🔓 Decrypted ✓';
                                                case 'not_needed': return '✓ No password needed';
                                                case 'failed': return '❌ Decryption failed';
                                                case 'skipped': return '⏭️ Skipped';
                                                default: return status;
                                            }
                                        };
                                        
                                        const formatSize = (bytes: number) => {
                                            if (bytes < 1024) return bytes + ' B';
                                            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
                                            return (bytes / 1024 / 1024).toFixed(1) + ' MB';
                                        };
                                        
                                        rowHtml += `
                                            <tr style="border-bottom: 1px solid #ddd;">
                                                <td colspan="3" style="padding: 10px; background-color: #f9f9f9;">
                                                    <div style="margin-top: 10px; border-top: 2px solid #eee; padding-top: 10px;">
                                                        <h4 style="color: #4285F4; margin: 5px 0;">📎 PDF Attachments Analyzed</h4>
                                                        <ul style="margin: 10px 0; padding-left: 20px;">
                                                            ${email.pdfAttachments.map(pdf => `
                                                                <li style="margin: 5px 0; font-size: 12px;">
                                                                    <strong>${escapeHtml(pdf.filename)}</strong> 
                                                                    (${formatSize(pdf.size)}) - 
                                                                    ${statusIcon(pdf.decryptionStatus)}
                                                                    ${pdf.error ? `<br/><span style="color: #d93025;">Error: ${escapeHtml(pdf.error)}</span>` : ''}
                                                                </li>
                                                            `).join('')}
                                                        </ul>
                                                    </div>
                                                    ${email.geminiAnalysis ? `
                                                        <div style="background: #e8f0fe; padding: 15px; border-radius: 5px; margin-top: 10px; border-left: 4px solid #4285F4;">
                                                            <strong style="color: #4285F4;">🤖 AI Insights:</strong>
                                                            <div style="margin-top: 10px; font-size: 12px; white-space: pre-wrap; line-height: 1.5;">${escapeHtml(email.geminiAnalysis)}</div>
                                                        </div>
                                                    ` : ''}
                                                </td>
                                            </tr>
                                        `;
                                    }
                                    
                                    return rowHtml;
                                }).join('')}
                            </table>
                        </div>
                    `;
                } else {
                    emailListHTML = '<p style="color: #666;">No unread emails found in the last 24 hours.</p>';
                }

                const htmlBody = `
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <style>
                            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                            .container { max-width: 700px; margin: 0 auto; padding: 20px; }
                            .header { background-color: #4285F4; color: white; padding: 20px; border-radius: 5px; text-align: center; }
                            .content { background-color: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
                            .stat { font-size: 24px; font-weight: bold; color: #4285F4; }
                            .label { color: #666; margin-top: 10px; }
                            .footer { font-size: 12px; color: #999; margin-top: 20px; text-align: center; }
                            table { background-color: white; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h1>📧 Your Email Insights Report</h1>
                            </div>
                            <div class="content">
                                <p>Hello,</p>
                                <p>Here's your email activity report for the last 24 hours:</p>
                                <div style="margin: 20px 0; padding: 15px; background-color: white; border-left: 4px solid #4285F4; border-radius: 3px; text-align: center;">
                                    <div class="stat">${newEmailCount}</div>
                                    <div class="label">Unread emails in your inbox</div>
                                </div>
                                ${emailListHTML}
                                <p style="margin-top: 20px; color: #666; font-size: 12px;">This report was generated on <strong>${new Date().toLocaleString()}</strong></p>
                            </div>
                            <div class="footer">
                                <p>This is an automated report from Mail Insights. Please do not reply to this email.</p>
                            </div>
                        </div>
                    </body>
                    </html>
                `;

                const emailSent = await sendEmailViaGmail(
                    gmail,
                    user.email,
                    '📧 Your Email Insights Report',
                    htmlBody
                );

                console.log(`   ✅ PROCESSED SUCCESSFULLY (Email sent: ${emailSent})`);
                
                processedUsers++;
                totalEmails += newEmailCount;
                results.push({
                    email: user.email,
                    status: 'success',
                    emailCount: newEmailCount,
                    emailDetails: emailDetails,
                    reportSent: emailSent
                });
            } catch (userError) {
                console.error(`   ❌ ERROR processing user: ${userError instanceof Error ? userError.message : String(userError)}`);
                results.push({
                    email: user.email,
                    status: 'error',
                    error: userError instanceof Error ? userError.message : String(userError)
                });
            }
        }

        const duration = Date.now() - startTime;
        console.log(`\n📧 ====== EMAIL PROCESSING COMPLETED ======`);
        console.log(`⏱️  Duration: ${duration}ms`);
        console.log(`✅ Processed users: ${processedUsers}/${users.length}`);
        console.log(`📊 Total emails found: ${totalEmails}`);

        res.status(200).json({ 
            message: 'Email processing complete',
            processedUsers,
            totalUsers: users.length,
            totalEmails,
            duration: `${duration}ms`,
            results
        });
    } catch (error) {
        const duration = Date.now() - startTime;
        console.error(`❌ FATAL ERROR in email processing (${duration}ms):`, error);
        res.status(500).json({ 
            error: 'Email processing failed',
            details: error instanceof Error ? error.message : String(error),
            duration: `${duration}ms`
        });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
