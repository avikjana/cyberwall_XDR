const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const dotenv = require('dotenv');
const redis = require('redis');

dotenv.config();

const app = express();
app.use(cors());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'UP', service: 'WebSocket Service' });
});

const server = http.createServer(app);

// Socket.IO Server configuration
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  },
  pingInterval: 25000,
  pingTimeout: 20000
});

const jwt = require('jsonwebtoken');
const ENGINE_API_KEY = process.env.API_KEY || 'cyberwall-xdr-engine-secret-token';
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretcyberwallxdrkey12345';

// Authenticate WebSocket Connections
io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;
  const apiKey = socket.handshake.auth?.apiKey || socket.handshake.query?.apiKey;

  // 1. Verify Engine connection via API Key
  if (apiKey && apiKey === ENGINE_API_KEY) {
    socket.user = { id: 'engine', username: 'firewall-engine', role: 'admin' };
    console.log('[WebSocket Service] Firewall Engine authenticated successfully via API Key.');
    return next();
  }

  // 2. Verify User socket connection via JWT
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.user = decoded;
      console.log(`[WebSocket Service] User ${decoded.username || decoded.id} authenticated.`);
      return next();
    } catch (err) {
      return next(new Error('Authentication error: Token invalid or expired'));
    }
  }

  return next(new Error('Authentication error: Access denied. Missing token or apiKey'));
});

// Redis Subscriber Setup
const redisClient = redis.createClient({
  url: process.env.REDIS_URL || 'redis://redis:6379'
});

redisClient.on('error', (err) => console.error('[WebSocket Service] Redis error:', err));

const initRedisSubscriber = async () => {
  try {
    await redisClient.connect();
    console.log('[WebSocket Service] Connected to Redis subscriber');

    // Subscribe to channels
    const channels = ['new_alert', 'alert_updated', 'new_traffic', 'block_ip', 'unblock_ip'];
    
    for (const channel of channels) {
      await redisClient.subscribe(channel, (message) => {
        try {
          const data = JSON.parse(message);
          console.log(`[WebSocket Service] Received Redis event [${channel}]`);
          
          if (channel === 'block_ip' || channel === 'unblock_ip') {
            // Broadcast firewall actions to all connected clients (including firewall engine)
            io.emit(channel, data);
          } else {
            // Send telemetry & threat updates to SOC analysts
            io.to('soc_channel').emit(channel, data);
          }
        } catch (e) {
          console.error(`[WebSocket Service] Failed to process Redis message: ${e.message}`);
        }
      });
    }
    console.log('[WebSocket Service] Subscribed to all Pub/Sub channels');
  } catch (error) {
    console.error('[WebSocket Service] Failed to initialize Redis subscriber:', error);
  }
};

initRedisSubscriber();

// Handle Socket.io connections
io.on('connection', (socket) => {
  console.log(`[WebSocket Service] New client connection: ${socket.id}`);

  socket.on('join_soc', () => {
    console.log(`[WebSocket Service] Client ${socket.id} joined SOC channel`);
    socket.join('soc_channel');
  });

  socket.on('disconnect', () => {
    console.log(`[WebSocket Service] Client disconnected: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 5003;
server.listen(PORT, () => {
  console.log(`WebSocket Service running on port ${PORT}`);
});
