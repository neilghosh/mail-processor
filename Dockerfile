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

COPY package*.json ./

RUN npm install --omit=dev

COPY --from=builder /usr/src/app/dist ./dist
COPY public ./public

CMD ["node", "dist/index.js"]