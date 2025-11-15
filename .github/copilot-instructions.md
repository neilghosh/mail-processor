# Copilot Instructions

## Project Overview

**mail-processor** is a Node.js/Express TypeScript service that processes Gmail emails and generates user insights reports. It uses Google OAuth2 for authentication, Datastore for user data persistence, and encrypts sensitive tokens (refresh/access tokens) with AES-256-CBC encryption.

**Key Architecture:**
- Express server with OAuth2 flow (`/auth/google` → `/auth/google/callback`)
- User credentials encrypted and stored in Google Datastore (see `src/utils/crypto.ts`)
- Email processing triggered via `POST /api/tasks/process-emails` (requires API key authentication)
- Generates HTML email reports sent via Gmail API

## Sensitive Data & Secrets

All secrets in `.env` file (never commit):
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` (OAuth2)
- `ENCRYPTION_KEY` (256-bit hex for AES-256-CBC token encryption)
- `API_KEY` (protects `/api/tasks/process-emails` endpoint)
- `GOOGLE_CLOUD_PROJECT_ID`, `GOOGLE_APPLICATION_CREDENTIALS` (local dev only; Cloud Run uses Application Default Credentials)

**Critical:** Refresh tokens are encrypted with `encrypt()` before storage. Always use `decrypt()` to retrieve them—never log decrypted tokens.

## Security Requirements

- **Always do a security review before committing:**
  - ✓ No hardcoded credentials; all secrets via environment variables
  - ✓ Token encryption: use `encrypt()`/`decrypt()` from `src/utils/crypto.ts` for OAuth tokens
  - ✓ Credential leakage: check logs via `sanitizeForLog()` helper (masks email addresses)
  - ✓ API authentication: `/api/tasks/process-emails` requires `Authorization: Bearer {API_KEY}` or `X-API-Key` header
  - ✓ Input validation: email addresses and OAuth code in query params are untrusted
  - ✓ Dependency vulnerabilities: run `npm audit` before commit

## Development Standards

**TypeScript & Code Style:**
- Use strict mode (`"strict": true` in `tsconfig.json`)
- Async/await for all async operations; catch errors explicitly
- Helper functions for cross-cutting concerns: `escapeHtml()`, `sanitizeForLog()`, `sendEmailViaGmail()`

**OAuth2 & Token Handling:**
- Refresh tokens preferred over access tokens for long-lived storage (see `src/index.ts` line ~220)
- If refresh token unavailable, warn and fall back to access token
- Always encrypt tokens before Datastore persistence

**Datastore Patterns:**
- User kind: `{ google_id, email, refreshToken, accessToken, tokenExpiry, createdAt }`
- EmailStat kind: stores batch processing results with timestamps and email details

**Error Handling:**
- Wrap external API calls (Gmail, Datastore) in try/catch with informative logging
- Return JSON error responses with HTTP status codes (401, 403, 500)
- Log helpful hints for OAuth permission errors (e.g., "gmail.send scope required")

## Build & Deployment

**Local Development:**
```bash
npm install         # Install dependencies
npm run build      # TypeScript → dist/
npm run dev        # nodemon with dotenv auto-loading
```

**Important:** For local development, comment out `REDIRECT_URI` in `.env`:
```bash
# REDIRECT_URI=https://mail-processor-926249069764.us-central1.run.app/auth/google/callback
```
This allows OAuth to redirect to `localhost:8080` instead of production URL.

**Cloud Run Deployment:**
- Use `deploy-cloud-run.sh`; set required env vars from `.env`
- Container: multi-stage Dockerfile (build stage strips devDependencies)
- Project ID: `demoneil`; Region: `us-central1`
- **Important:** Uncomment `REDIRECT_URI` in `.env` for production deployment

## Testing the Application Locally

### 1. Start the Server
```bash
# For persistent background server (recommended for remote SSH):
cd /Users/neilghosh/dev/mail-processor
nohup npm run dev >> ~/mail-server.log 2>&1 < /dev/null &
disown

# Monitor logs:
tail -f ~/mail-server.log

# Stop server:
pkill -f "nodemon.*index.ts"
```

### 2. Authenticate with Google OAuth
**Local access:**
```bash
# Open in browser
open http://localhost:8080/auth/google
```

**Remote SSH access (optional):**
If the server is on a remote machine, set up SSH port forwarding:

**Option A - Command Line:**
```bash
ssh -L 8080:localhost:8080 user@remote-server
```

**Option B - Chromebook Linux Terminal:**
```bash
# Enable Linux (Beta) in Settings → Developers
ssh -L 8080:localhost:8080 user@remote-server-ip
```

**Option C - Chrome Secure Shell Extension:**
Add to "SSH Arguments": `-L8080:localhost:8080`

Then open `http://localhost:8080/auth/google` in your local browser.

### 3. Test Email Processing
```bash
# Get API key from .env
API_KEY=$(grep "^API_KEY=" .env | cut -d'=' -f2)

# Trigger email processing
curl -X POST http://localhost:8080/api/tasks/process-emails \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json"

# Monitor processing logs
tail -f ~/mail-server.log
```

### 4. Verify Results
- Check Gmail inbox for "📧 Your Email Insights Report"
- Review server logs for processing stats
- Verify Datastore entries in Google Cloud Console

**Testing Endpoints:**
```bash
# Health check
curl http://localhost:8080

# OAuth flow
curl http://localhost:8080/auth/google

# Email processing (requires API key)
curl -X POST http://localhost:8080/api/tasks/process-emails \
  -H "X-API-Key: {your-api-key-from-.env}"
```

## Code Quality

- **Linting:** No current linter configured; add ESLint + Prettier before production
- **Logging:** Debug logs include folder detection and token info; strip before Cloud Run
- **Console logs:** OK for debugging; remove or convert to debug-level before final commit
- **Email HTML:** Built inline (see `sendEmailViaGmail()` htmlBody); sanitize with `escapeHtml()` if user data injected
- **Dependencies up to date:** Current versions in `package.json` as of ~Q4 2023; audit regularly

## Key Files & Patterns

- **`src/index.ts`:** Main server, routes, Datastore queries, Gmail API calls, email generation
- **`src/utils/crypto.ts`:** `encrypt()`/`decrypt()` using AES-256-CBC; `ENCRYPTION_KEY` from env
- **`.env.example`:** Template for setup; `.env` excluded from git
- **`setup.sh`:** Interactive setup; generates `ENCRYPTION_KEY` and `API_KEY`
- **`GEMINI.md`:** AI coding guidelines (ignore if using Copilot; follow this file instead)
