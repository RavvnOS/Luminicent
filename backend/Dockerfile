# Backend Dockerfile for Luminicent DevOps Simulator
FROM node:18-alpine

WORKDIR /app

# Install system dependencies if required (e.g. curl for healthchecks)
RUN apk add --no-cache curl

# Install Node dependencies
COPY package*.json ./
RUN npm install --production

# Copy backend source code
COPY . .

# Create uploads folder
RUN mkdir -p uploads

# Expose backend API port
EXPOSE 5000

ENV PORT=5000
ENV NODE_ENV=production

# Health check endpoint verification
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/api/health || exit 1


CMD ["node", "server.js"]
