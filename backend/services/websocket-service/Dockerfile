FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY services/websocket-service/ ./services/websocket-service/
EXPOSE 5003
CMD ["node", "services/websocket-service/server.js"]
