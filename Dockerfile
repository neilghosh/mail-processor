FROM node:18-slim as builder

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY tsconfig.json ./
COPY src ./src

RUN npm run build

# Production stage
FROM node:18-slim

# Install qpdf for PDF decryption
RUN apt-get update && apt-get install -y qpdf && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Create a non-root user to run the application
RUN groupadd -r nodeuser && useradd -r -g nodeuser nodeuser

COPY package*.json ./

RUN npm install --omit=dev

COPY --from=builder /usr/src/app/dist ./dist
COPY public ./public

# Create temp directory with proper permissions
RUN mkdir -p /tmp/mail-attachments && chown -R nodeuser:nodeuser /tmp/mail-attachments

# Change ownership of application files
RUN chown -R nodeuser:nodeuser /usr/src/app

# Switch to non-root user
USER nodeuser

CMD ["node", "dist/index.js"]