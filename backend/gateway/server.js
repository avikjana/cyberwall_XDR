const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const dotenv = require('dotenv');
const compression = require('compression');
const { createProxyMiddleware } = require('http-proxy-middleware');

dotenv.config();

const app = express();

// Standard middlewares
app.use(helmet());
app.use(cors());
app.use(compression());

if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Stricter rate-limiting for auth endpoints to prevent brute-force attacks
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'development' ? 1000 : 20, // max 20 login/register tries
  message: { success: false, error: 'Too many authentication attempts. Please try again in 15 minutes.' }
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Centralized request validation & Injection prevention middleware
app.use((req, res, next) => {
  const hasInjection = (value) => {
    if (typeof value === 'string') {
      // Basic NoSQL / SQL injection signature signatures check
      const sqliPattern = /(UNION\s+SELECT|OR\s+['"]1['"]\s*=\s*['"]1|SELECT\s+.*\s+FROM)/i;
      const nosqlPattern = /(\$gt|\$ne|\$where|\$regex)/i;
      return sqliPattern.test(value) || nosqlPattern.test(value);
    } else if (typeof value === 'object' && value !== null) {
      return Object.values(value).some(hasInjection);
    }
    return false;
  };

  if (hasInjection(req.body) || hasInjection(req.query)) {
    return res.status(400).json({ success: false, error: 'Request blocked by gateway: Potential injection attack detected' });
  }
  next();
});

// General rate limiter for all other API endpoints
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'development' ? 100000 : 300,
  message: { success: false, error: 'Too many requests from this IP, please try again later.' }
});
app.use('/api/', limiter);

// Proxy definition
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://auth-service:5001';
const THREAT_SERVICE_URL = process.env.THREAT_SERVICE_URL || 'http://threat-service:5002';
const WEBSOCKET_SERVICE_URL = process.env.WEBSOCKET_SERVICE_URL || 'http://websocket-service:5003';
const TI_SERVICE_URL = process.env.TI_SERVICE_URL || 'http://threat-intelligence:5004';
const SIEM_SERVICE_URL = process.env.SIEM_SERVICE_URL || 'http://siem-service:5005';

// 1. Auth Service Routes
app.use('/api/auth', createProxyMiddleware({
  target: AUTH_SERVICE_URL,
  changeOrigin: true,
  pathRewrite: {
    '^/api/auth': '/api/auth'
  }
}));

// 2. WebSocket Service proxy (for direct websocket connections to port 5000)
app.use('/socket.io', createProxyMiddleware({
  target: WEBSOCKET_SERVICE_URL,
  changeOrigin: true,
  ws: true
}));

// 3. Threat & Analytics Service Routes
const threatPaths = ['/api/alerts', '/api/traffic', '/api/rules', '/api/analytics'];
threatPaths.forEach(path => {
  app.use(path, createProxyMiddleware({
    target: THREAT_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: (pathStr) => pathStr // preserve entire path e.g. /api/alerts
  }));
});

// 4. Threat Intelligence Service Routes
app.use('/api/ti', createProxyMiddleware({
  target: TI_SERVICE_URL,
  changeOrigin: true,
  pathRewrite: (pathStr) => pathStr // preserve entire path e.g. /api/ti/enrich/ip
}));

// 5. SIEM & Big Data Analytics Service Routes
app.use('/api/siem', createProxyMiddleware({
  target: SIEM_SERVICE_URL,
  changeOrigin: true,
  pathRewrite: (pathStr) => pathStr // preserve entire path e.g. /api/siem/search
}));

// Gateway health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'UP', service: 'CyberWall XDR API Gateway' });
});

// Default error handler
app.use((err, req, res, next) => {
  console.error('[Gateway Error]', err.stack || err.message);
  res.status(500).json({
    success: false,
    error: 'Gateway routing error. Downstream service may be unavailable.'
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`CyberWall XDR API Gateway running on port ${PORT}`);
});
