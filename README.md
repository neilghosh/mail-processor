# Mail Processor

Node.js/Express TypeScript service that processes Gmail emails and generates user insights reports using Google OAuth2, Datastore, and Gmail API.

## Features

- Google OAuth2 authentication
- Gmail email fetching and analysis
- Automated email insights reports
- AES-256-CBC token encryption
- Google Datastore persistence

## Prerequisites

- Node.js (v18+)
- Google Cloud Project with Gmail API enabled
- Google OAuth2 credentials
- Google Cloud Datastore access

## Local Development Setup

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` and fill in your credentials:
```bash
cp .env.example .env
```

Or run the interactive setup:
```bash
./setup.sh
```

Required variables:
- `GOOGLE_CLIENT_ID` - OAuth2 client ID
- `GOOGLE_CLIENT_SECRET` - OAuth2 client secret
- `ENCRYPTION_KEY` - 256-bit hex key for token encryption
- `API_KEY` - API key for protected endpoints
- `GOOGLE_CLOUD_PROJECT_ID` - GCP project ID
- `GOOGLE_APPLICATION_CREDENTIALS` - Path to service account JSON

**Important:** For local development, comment out `REDIRECT_URI` in `.env`:
```bash
# REDIRECT_URI=https://your-production-url/auth/google/callback
```

### 3. Start the Development Server
```bash
npm run dev
```

Server will start on `http://localhost:8080`

### 4. Authenticate with Google
Open your browser to:
```
http://localhost:8080/auth/google
```

Sign in with your Google account to authorize Gmail access.

### 5. Trigger Email Processing
```bash
curl -X POST http://localhost:8080/api/tasks/process-emails \
  -H "X-API-Key: YOUR_API_KEY_FROM_ENV" \
  -H "Content-Type: application/json"
```

Check your Gmail for the insights report email!

## Remote SSH Access (Optional)

If running the server on a remote machine and accessing from a local browser:

### Option 1: SSH Port Forwarding (Command Line)
```bash
ssh -L 8080:localhost:8080 user@remote-server
```

Then open `http://localhost:8080/auth/google` in your local browser.

### Option 2: Chromebook Linux Terminal
1. Enable Linux (Beta) in Chromebook settings
2. Open Linux Terminal
3. Run:
   ```bash
   ssh -L 8080:localhost:8080 user@remote-server-ip
   ```
4. Keep terminal open and browse to `http://localhost:8080/auth/google`

### Option 3: Chrome Secure Shell Extension
In "SSH Arguments" field, add:
```
-L8080:localhost:8080
```

## Production Deployment

Deploy to Google Cloud Run:
```bash
./deploy-cloud-run.sh
```

Make sure to:
1. Uncomment `REDIRECT_URI` in `.env` with your Cloud Run URL
2. Set all environment variables in Cloud Run
3. Configure OAuth2 redirect URIs in Google Cloud Console

## Scripts

- `npm run dev` - Start development server with hot reload
- `npm run build` - Compile TypeScript to JavaScript
- `npm start` - Run production build (requires env vars)

## Security Notes

- Never commit `.env` file
- All OAuth tokens are encrypted before storage
- API endpoints require authentication
- Use `sanitizeForLog()` for sensitive data in logs

## Architecture

- **Express** - Web framework
- **TypeScript** - Type safety
- **Google Datastore** - User data persistence
- **Gmail API** - Email fetching and sending
- **OAuth2** - Google authentication
- **AES-256-CBC** - Token encryption