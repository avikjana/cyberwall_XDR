const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const dotenv = require('dotenv');
const compression = require('compression');
const connectDB = require('./config/db');

// Load environment variables
dotenv.config();

// Connect to MongoDB
connectDB();

const app = express();
const server = http.createServer(app);

// Socket.IO configuration
const io = socketIo(server, {
  cors: {
    origin: '*', // Customize in production deployment
    methods: ['GET', 'POST']
  },
  // Performance: reduce ping frequency for less overhead
  pingInterval: 25000,
  pingTimeout: 20000
});

// Make socket.io instance globally accessible
global.io = io;

// Setup Middlewares
app.use(helmet());
app.use(cors());
// Gzip compression — reduces JSON response size by 60-80%
app.use(compression());
// Limit JSON payload size to prevent oversized requests from consuming excess memory
app.use(express.json({ limit: '1mb' }));
// Only use morgan logging in development — skip in production for throughput
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Rate Limiting to prevent brute-force/DDoS on APIs
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'development' ? 100000 : 300, // limit each IP to 300 requests per windowMs
  message: { success: false, error: 'Too many requests from this IP, please try again later.' }
});
app.use('/api/', limiter);

// Mount Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/alerts', require('./routes/alerts'));
app.use('/api/traffic', require('./routes/traffic'));
app.use('/api/rules', require('./routes/rules'));
app.use('/api/analytics', require('./routes/analytics'));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'UP', service: 'CyberWall XDR Backend' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error'
  });
});

// Handle WebSocket connections
io.on('connection', (socket) => {
  console.log(`New client connected: ${socket.id}`);

  socket.on('join_soc', () => {
    console.log(`Client ${socket.id} joined SOC channel`);
    socket.join('soc_channel');
  });

  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`CyberWall XDR Backend running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});
