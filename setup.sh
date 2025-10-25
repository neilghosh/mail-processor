#!/bin/bash

# Create the .env file if it doesn't exist
if [ ! -f .env ]; then
    touch .env
    echo "Created .env file."
fi

# Source existing .env file to load variables
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Ask for credentials only if they are not already set
if [ -z "$GOOGLE_CLIENT_ID" ]; then
    read -p "Enter your GOOGLE_CLIENT_ID: " GOOGLE_CLIENT_ID
fi

if [ -z "$GOOGLE_CLIENT_SECRET" ]; then
    read -p "Enter your GOOGLE_CLIENT_SECRET: " GOOGLE_CLIENT_SECRET
fi

# Generate encryption key only if it's not already set
if [ -z "$ENCRYPTION_KEY" ]; then
    echo "Generating new ENCRYPTION_KEY..."
    ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
fi

# Write the (potentially updated) environment variables to the .env file
echo "GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}" > .env
echo "GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}" >> .env
echo "ENCRYPTION_KEY=${ENCRYPTION_KEY}" >> .env

echo ".env file configured successfully."

# Build the application
echo "Building the TypeScript application..."
npm run build

# Start the application
echo "Starting the application..."
npm start
