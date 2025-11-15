# Mail Processor with PDF Analysis

A Node.js + Express service that processes Gmail emails and analyzes PDF attachments using Google's Gemini AI.

## Features

- **Email Processing**: Automatically fetches and processes unread emails from Gmail
- **PDF Attachment Handling**: 
  - Extracts PDF attachments from emails (up to 5 per email, max 10MB each)
  - Decrypts password-protected PDFs using keyword-based password matching
  - Supports qpdf for PDF decryption
- **AI-Powered Analysis**: 
  - Analyzes PDFs with Google's Gemini 1.5 Flash model
  - Subject-based prompt matching for contextual analysis (invoices, receipts, reports, contracts, statements)
- **Email Reports**: Sends detailed HTML email reports with PDF insights and AI analysis
- **Secure Storage**: Uses Google Cloud Datastore for user tokens and email statistics

## Prerequisites

- Node.js 18 or higher
- Google Cloud Project with:
  - Gmail API enabled
  - Datastore API enabled
  - Service account credentials (for local development)
- Gemini API key (for PDF analysis)
- qpdf installed (for PDF decryption)

## Installation

### 1. Install Dependencies

```bash
npm install
```

### 2. Install qpdf

**macOS:**
```bash
brew install qpdf
```

**Ubuntu/Debian:**
```bash
apt-get install qpdf
```

### 3. Configure Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Or use the interactive setup script:

```bash
./setup.sh
```

Required environment variables:
- `GOOGLE_CLIENT_ID`: OAuth2 client ID from Google Cloud Console
- `GOOGLE_CLIENT_SECRET`: OAuth2 client secret
- `GOOGLE_CLOUD_PROJECT_ID`: Your Google Cloud project ID
- `ENCRYPTION_KEY`: 256-bit encryption key for storing tokens
- `API_KEY`: API key for authenticating requests to the service
- `GEMINI_API_KEY`: API key for Gemini AI (get from https://makersuite.google.com/app/apikey)
- `PDF_PASSWORDS`: JSON map of subject keywords to PDF passwords (e.g., `{"invoice":"pass123"}`)

## Usage

### Development

```bash
npm run dev
```

### Production

```bash
npm run build
npm start
```

## API Endpoints

### Authentication

**GET** `/auth/google`
- Initiates Google OAuth2 authentication flow
- Redirects to Google consent screen
- Required scopes: gmail.readonly, gmail.send, userinfo.email, userinfo.profile

**GET** `/auth/google/callback`
- OAuth2 callback endpoint
- Stores encrypted tokens in Datastore

### Email Processing

**POST** `/api/tasks/process-emails`
- Processes unread emails from the last 24 hours for all authenticated users
- Requires API key authentication (via `Authorization: Bearer <key>` or `x-api-key` header)
- Response includes:
  - Number of users processed
  - Total emails found
  - Processing results per user

## PDF Processing Features

### Automatic PDF Extraction
The service automatically:
1. Detects PDF attachments in emails
2. Downloads PDFs (skips files > 10MB)
3. Checks if PDFs are password-protected

### Password-Based Decryption
Configure PDF passwords in the `PDF_PASSWORDS` environment variable:

```bash
PDF_PASSWORDS='{"invoice":"password1","receipt":"password2","report":"password3"}'
```

The service matches subject line keywords (case-insensitive) to decrypt PDFs.

### AI Analysis with Gemini

PDFs are analyzed based on subject line keywords:

| Keyword | Analysis Type |
|---------|--------------|
| invoice | Extract vendor name, invoice number, total amount, date, line items |
| receipt | Summarize merchant, total, date, payment method, items |
| report | Analyze key insights, findings, recommendations |
| contract | Extract parties, dates, termination clauses, obligations |
| statement | Summarize period, account details, transactions, balances |

Analysis results are included in the email report sent to users.

## Deployment

### Docker

Build the Docker image:

```bash
docker build -t mail-processor .
```

Run the container:

```bash
docker run -p 8080:8080 --env-file .env mail-processor
```

### Google Cloud Run

Use the provided deployment script:

```bash
./deploy-cloud-run.sh
```

Make sure to set the required environment variables in Cloud Run:
- GOOGLE_CLIENT_ID
- GOOGLE_CLIENT_SECRET
- ENCRYPTION_KEY
- API_KEY
- GEMINI_API_KEY
- PDF_PASSWORDS

## Security

- OAuth tokens are encrypted using AES-256-CBC before storage
- API endpoints require authentication
- Shell commands properly escape user input to prevent injection
- Temporary PDF files are cleaned up after processing
- No sensitive data is logged

## Project Structure

```
.
├── src/
│   ├── index.ts           # Main Express server and email processing logic
│   └── utils/
│       ├── crypto.ts      # Token encryption/decryption utilities
│       ├── pdf.ts         # PDF download, decryption, extraction utilities
│       └── gemini.ts      # Gemini AI integration for PDF analysis
├── public/                # Static files
├── views/                 # HTML templates
├── Dockerfile             # Docker configuration with qpdf
├── package.json           # Dependencies and scripts
└── .env.example           # Environment variable template
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `npm run build` to verify
5. Submit a pull request

## License

MIT