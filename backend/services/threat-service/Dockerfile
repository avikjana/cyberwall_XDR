FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY shared/ ./shared/
COPY services/threat-service/ ./services/threat-service/
EXPOSE 5002
CMD ["node", "services/threat-service/server.js"]
