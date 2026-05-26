FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY gateway/ ./gateway/
EXPOSE 5000
CMD ["node", "gateway/server.js"]
