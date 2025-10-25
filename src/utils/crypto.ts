
import * as crypto from 'crypto';

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

// Get the secret from environment variables
const secret = process.env.ENCRYPTION_KEY;

// Ensure the secret key is defined
if (!secret) {
    throw new Error('ENCRYPTION_KEY environment variable is not set. Please define it in your .env file.');
}

// Use a SHA-256 hash of the secret to generate a 32-byte key. This is a secure way to get the required key length.
const ENCRYPTION_KEY = crypto.createHash('sha256').update(secret).digest();

/**
 * Encrypts a string using aes-256-cbc.
 * A random Initialization Vector (IV) is generated for each encryption.
 */
export function encrypt(text: string): string {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

/**
 * Decrypts a string encrypted with aes-256-cbc.
 */
export function decrypt(text: string): string {
    const textParts = text.split(':');
    const ivString = textParts.shift();

    if (!ivString) {
        throw new Error("Invalid encrypted text format: IV is missing.");
    }

    const iv = Buffer.from(ivString, 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    return decrypted.toString();
}
