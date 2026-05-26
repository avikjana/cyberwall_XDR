FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
COPY services/siem-service/package*.json ./services/siem-service/
RUN cd services/siem-service && npm install --omit=dev
COPY shared/ ./shared/
COPY services/siem-service/ ./services/siem-service/
EXPOSE 5005
CMD ["node", "services/siem-service/server.js"]
