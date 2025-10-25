#!/bin/bash

# Cloud Run Deployment Script
# This script deploys the mail-processor service to Google Cloud Run

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="demoneil"
SERVICE_NAME="mail-processor"
IMAGE_URL="us-central1-docker.pkg.dev/${PROJECT_ID}/mail-processor/mail-processor:latest"
REGION="us-central1"
MEMORY="1Gi"
CPU="1"
TIMEOUT="3600s"
MAX_INSTANCES="100"

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Cloud Run Deployment${NC}"
echo -e "${BLUE}================================${NC}\n"

# Check if required tools are installed
for tool in gcloud; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}Error: $tool is not installed${NC}"
        exit 1
    fi
done

# Verify project
CURRENT_PROJECT=$(gcloud config get-value project)
if [ "$CURRENT_PROJECT" != "$PROJECT_ID" ]; then
    echo -e "${YELLOW}Setting project to ${PROJECT_ID}...${NC}"
    gcloud config set project $PROJECT_ID
fi

echo -e "${YELLOW}Loading environment variables from .env file...${NC}\n"

# Source .env file if it exists
if [ ! -f .env ]; then
    echo -e "${RED}Error: .env file not found. Please run setup.sh first.${NC}"
    exit 1
fi

# Load environment variables from .env
set -a
source .env
set +a

# Validate required environment variables
REQUIRED_VARS=("GOOGLE_CLIENT_ID" "GOOGLE_CLIENT_SECRET" "ENCRYPTION_KEY" "API_KEY" "PORT" "NODE_ENV" "REDIRECT_URI")

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo -e "${RED}Error: Required environment variable '$var' is not set${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✓ All required environment variables are set${NC}\n"

# Construct gcloud run deploy command with environment variables
echo -e "${BLUE}Deploying ${SERVICE_NAME} to Cloud Run...${NC}\n"

gcloud run deploy $SERVICE_NAME \
    --image=$IMAGE_URL \
    --region=$REGION \
    --memory=$MEMORY \
    --cpu=$CPU \
    --timeout=$TIMEOUT \
    --max-instances=$MAX_INSTANCES \
    --platform=managed \
    --allow-unauthenticated \
    --set-env-vars=" \
GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID},\
GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET},\
ENCRYPTION_KEY=${ENCRYPTION_KEY},\
API_KEY=${API_KEY},\
NODE_ENV=${NODE_ENV},\
REDIRECT_URI=${REDIRECT_URI},\
GOOGLE_CLOUD_PROJECT=${PROJECT_ID}"

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Deployment failed${NC}"
    exit 1
fi

echo -e "\n${GREEN}✓ Deployment completed successfully!${NC}\n"

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region=$REGION --format='value(status.url)')

echo -e "${BLUE}Deployment Summary:${NC}"
echo "===================="
echo -e "Service Name: ${GREEN}${SERVICE_NAME}${NC}"
echo -e "Region: ${GREEN}${REGION}${NC}"
echo -e "Image: ${GREEN}${IMAGE_URL}${NC}"
echo -e "Service URL: ${GREEN}${SERVICE_URL}${NC}"
echo -e "Memory: ${GREEN}${MEMORY}${NC}"
echo -e "CPU: ${GREEN}${CPU}${NC}"
echo -e "Max Instances: ${GREEN}${MAX_INSTANCES}${NC}"
echo -e "Timeout: ${GREEN}${TIMEOUT}${NC}"
echo "===================="
echo -e "\n${YELLOW}Environment Variables Deployed:${NC}"
echo "- GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID:0:20}..."
echo "- GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET:0:20}..."
echo "- ENCRYPTION_KEY: ${ENCRYPTION_KEY:0:20}..."
echo "- API_KEY: ${API_KEY:0:20}..."
echo "- PORT: ${PORT}"
echo "- NODE_ENV: ${NODE_ENV}"
echo "- REDIRECT_URI: ${REDIRECT_URI}"
echo ""

# Show how to invoke the API
echo -e "${BLUE}API Endpoints:${NC}"
echo "=============="
echo -e "${GREEN}Authentication:${NC}"
echo "  GET ${SERVICE_URL}/auth/google"
echo ""
echo -e "${GREEN}Process Emails (Protected):${NC}"
echo "  POST ${SERVICE_URL}/api/tasks/process-emails"
echo "  Headers:"
echo "    - Authorization: Bearer ${API_KEY:0:20}..."
echo "    OR"
echo "    - X-API-Key: ${API_KEY:0:20}..."
echo ""

# Offer to view logs
read -p "Do you want to view the service logs? (y/n): " VIEW_LOGS

if [ "$VIEW_LOGS" = "y" ] || [ "$VIEW_LOGS" = "Y" ]; then
    echo -e "${BLUE}Fetching logs...${NC}\n"
    gcloud run services describe $SERVICE_NAME --region=$REGION
fi

echo -e "${GREEN}Deployment script completed!${NC}"
