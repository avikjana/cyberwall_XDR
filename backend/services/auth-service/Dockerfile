FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY shared/ ./shared/
COPY services/auth-service/ ./services/auth-service/
EXPOSE 5001
CMD ["node", "services/auth-service/server.js"]
