# Stage 1 — Build stage
FROM node:20-alpine AS builder

# Set working directory inside container
WORKDIR /app

# Copy only package.json and package-lock.json
COPY package*.json ./

# Install production dependencies only
RUN npm install --production

# Copy the entire project
COPY . .

# Stage 2 — Runtime stage
FROM node:20-alpine

WORKDIR /app

# Only copy necessary files from builder stage
COPY --from=builder /app ./

# Expose the app port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
