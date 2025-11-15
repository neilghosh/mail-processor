
import { GoogleGenerativeAI, GenerativeModel } from '@google/generative-ai';
import { GoogleAIFileManager } from '@google/generative-ai/server';
import * as mime from 'mime-types';
import { PdfProcessingResult } from './pdf';

// Subject to Prompt mapping
const SUBJECT_TO_PROMPT_MAP: { [key: string]: string } = {
    'invoice': 'Extract invoice details including vendor name, invoice number, total amount, date, and line items.',
    'receipt': 'Summarize this receipt: merchant name, total amount, date, payment method, and items purchased.',
    'report': 'Analyze this report and provide key insights, findings, and recommendations.',
    'contract': 'Extract key contract terms: parties involved, effective dates, termination clauses, and primary obligations.',
    'statement': 'Summarize this statement: period, account details, transactions, and balances.'
};

/**
 * Get the appropriate prompt for a given subject
 */
export function getPromptForSubject(subject: string): string | null {
    const subjectLower = subject.toLowerCase();
    
    // Find first matching keyword (case-insensitive)
    for (const [keyword, prompt] of Object.entries(SUBJECT_TO_PROMPT_MAP)) {
        if (subjectLower.includes(keyword.toLowerCase())) {
            console.log(`      💡 Found prompt match for keyword: ${keyword}`);
            return prompt;
        }
    }
    
    return null;
}

/**
 * Upload a file to Gemini for analysis
 */
export async function uploadFileToGemini(filePath: string, mimeType: string): Promise<string> {
    const apiKey = process.env.GEMINI_API_KEY;
    
    if (!apiKey) {
        throw new Error('GEMINI_API_KEY environment variable is not set');
    }

    const fileManager = new GoogleAIFileManager(apiKey);
    
    console.log(`      📤 Uploading file to Gemini...`);
    
    const uploadResult = await fileManager.uploadFile(filePath, {
        mimeType,
        displayName: filePath.split('/').pop() || 'document.pdf'
    });
    
    console.log(`      ✅ File uploaded: ${uploadResult.file.uri}`);
    
    return uploadResult.file.uri;
}

/**
 * Analyze a single PDF with Gemini
 */
export async function analyzePdfWithGemini(
    filePath: string,
    prompt: string,
    filename: string
): Promise<string> {
    const apiKey = process.env.GEMINI_API_KEY;
    
    if (!apiKey) {
        throw new Error('GEMINI_API_KEY environment variable is not set');
    }

    try {
        console.log(`      🤖 Analyzing ${filename} with Gemini...`);
        
        // Get mime type
        const mimeType = mime.lookup(filePath) || 'application/pdf';
        
        // Upload file
        const fileUri = await uploadFileToGemini(filePath, mimeType);
        
        // Initialize Gemini
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
        
        // Generate content with timeout
        const timeoutPromise = new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('Gemini API timeout (30 seconds)')), 30000);
        });
        
        const analysisPromise = model.generateContent([
            {
                fileData: {
                    mimeType,
                    fileUri
                }
            },
            { text: prompt }
        ]);
        
        const result = await Promise.race([analysisPromise, timeoutPromise]);
        const response = result.response;
        const text = response.text();
        
        console.log(`      ✅ Analysis complete for ${filename}`);
        
        return text;
    } catch (error: any) {
        console.error(`      ❌ Gemini analysis failed for ${filename}:`, error.message);
        throw error;
    }
}

/**
 * Analyze multiple PDFs and combine results
 */
export async function analyzeMultiplePdfs(
    pdfResults: PdfProcessingResult[],
    prompt: string
): Promise<string> {
    const analyses: string[] = [];
    
    // Filter for successfully processed PDFs
    const successfulPdfs = pdfResults.filter(
        pdf => pdf.filePath && (pdf.decryptionStatus === 'success' || pdf.decryptionStatus === 'not_needed')
    );
    
    if (successfulPdfs.length === 0) {
        return 'No PDFs available for analysis.';
    }
    
    console.log(`      📊 Analyzing ${successfulPdfs.length} PDF(s)...`);
    
    // Analyze each PDF separately
    for (const pdf of successfulPdfs) {
        try {
            const analysis = await analyzePdfWithGemini(pdf.filePath!, prompt, pdf.filename);
            analyses.push(`\n**Analysis of ${pdf.filename}:**\n${analysis}`);
        } catch (error: any) {
            console.error(`      ⚠️  Skipping ${pdf.filename} due to error:`, error.message);
            analyses.push(`\n**${pdf.filename}:** Analysis failed - ${error.message}`);
        }
    }
    
    return analyses.join('\n\n---\n');
}
