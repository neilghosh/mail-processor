#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Mail Processor Setup Script${NC}"
echo -e "${BLUE}================================${NC}\n"

# Create the .env file if it doesn't exist
if [ ! -f .env ]; then
    touch .env
    echo -e "${GREEN}✓ Created .env file${NC}"
fi

# Source existing .env file to load variables
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

echo -e "\n${YELLOW}Please provide the following configuration:${NC}\n"

# Ask for GOOGLE_CLIENT_ID
if [ -z "$GOOGLE_CLIENT_ID" ]; then
    read -p "Enter your GOOGLE_CLIENT_ID: " GOOGLE_CLIENT_ID
else
    echo "GOOGLE_CLIENT_ID already set (${GOOGLE_CLIENT_ID:0:20}...)"
fi

# Ask for GOOGLE_CLIENT_SECRET
if [ -z "$GOOGLE_CLIENT_SECRET" ]; then
    read -p "Enter your GOOGLE_CLIENT_SECRET: " GOOGLE_CLIENT_SECRET
else
    echo "GOOGLE_CLIENT_SECRET already set (${GOOGLE_CLIENT_SECRET:0:20}...)"
fi

# Ask for GOOGLE_CLOUD_PROJECT_ID (local only)
if [ -z "$GOOGLE_CLOUD_PROJECT_ID" ]; then
    read -p "Enter your GOOGLE_CLOUD_PROJECT_ID (local only, leave blank for Cloud Run): " GOOGLE_CLOUD_PROJECT_ID
else
    echo "GOOGLE_CLOUD_PROJECT_ID already set ($GOOGLE_CLOUD_PROJECT_ID)"
fi

# Ask for GOOGLE_APPLICATION_CREDENTIALS path (local only)
if [ -z "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
    read -p "Enter path to GOOGLE_APPLICATION_CREDENTIALS (leave blank for Cloud Run/cloud environments): " GOOGLE_APPLICATION_CREDENTIALS
else
    echo "GOOGLE_APPLICATION_CREDENTIALS already set ($GOOGLE_APPLICATION_CREDENTIALS)"
fi

# Generate encryption key only if it's not already set
if [ -z "$ENCRYPTION_KEY" ]; then
    echo -e "\n${YELLOW}Generating new ENCRYPTION_KEY...${NC}"
    ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
    echo -e "${GREEN}✓ Generated ENCRYPTION_KEY${NC}"
fi

# Generate API_KEY only if it's not already set
if [ -z "$API_KEY" ]; then
    echo -e "${YELLOW}Generating new API_KEY for email processing endpoint...${NC}"
    API_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
    echo -e "${GREEN}✓ Generated API_KEY${NC}"
fi

# Optional: Ask for PORT
if [ -z "$PORT" ]; then
    read -p "Enter PORT (default: 8080): " PORT
    PORT=${PORT:-8080}
else
    echo "PORT already set ($PORT)"
fi

# Optional: Ask for NODE_ENV
if [ -z "$NODE_ENV" ]; then
    read -p "Enter NODE_ENV (development/production, default: development): " NODE_ENV
    NODE_ENV=${NODE_ENV:-development}
else
    echo "NODE_ENV already set ($NODE_ENV)"
fi

# Write all environment variables to .env file
echo -e "\n${YELLOW}Writing configuration to .env...${NC}"

cat > .env << EOF
# Google OAuth
GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}

# Google Cloud (optional - only for local development)
# Cloud Run automatically provides GOOGLE_CLOUD_PROJECT via ADC
# Leave empty when deploying to Cloud Run
GOOGLE_CLOUD_PROJECT_ID=${GOOGLE_CLOUD_PROJECT_ID}
GOOGLE_APPLICATION_CREDENTIALS=${GOOGLE_APPLICATION_CREDENTIALS}

# Encryption
ENCRYPTION_KEY=${ENCRYPTION_KEY}

# API Security
API_KEY=${API_KEY}

# Server Configuration
PORT=${PORT}
NODE_ENV=${NODE_ENV}

# OAuth Redirect URI (update if different from localhost)
OAUTH_REDIRECT_URI=http://localhost:${PORT}/auth/google/callback
EOF

echo -e "${GREEN}✓ .env file configured successfully${NC}\n"

# Display summary
echo -e "${BLUE}Configuration Summary:${NC}"
echo "========================"
echo "Google Client ID: ${GOOGLE_CLIENT_ID:0:20}..."
echo "Google Cloud Project: $GOOGLE_CLOUD_PROJECT_ID"
echo "Encryption Key: ${ENCRYPTION_KEY:0:20}..."
echo "API Key: ${API_KEY:0:20}..."
echo "Server Port: $PORT"
echo "Environment: $NODE_ENV"
echo "========================\n"

# Install dependencies
echo -e "${BLUE}Installing dependencies...${NC}"
npm install

if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Warning: npm install encountered an issue${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Dependencies installed${NC}\n"

# Build the application
echo -e "${BLUE}Building the TypeScript application...${NC}"
npm run build

if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Error: Build failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Build completed successfully${NC}\n"

# Offer to start the application
echo -e "${BLUE}Setup completed!${NC}"
echo -e "${GREEN}✓ Configuration complete and application built${NC}\n"

read -p "Do you want to start the application now? (y/n): " START_APP

if [ "$START_APP" = "y" ] || [ "$START_APP" = "Y" ]; then
    echo -e "${BLUE}Starting the application...${NC}\n"
    npm run dev
else
    echo -e "${YELLOW}To start the application, run: npm run dev${NC}"
fi
