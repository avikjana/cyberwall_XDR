const jwt = require('jsonwebtoken');
const User = require('../models/user');

// ─── Lightweight LRU user cache ──────────────────────────────────────────────
// Avoids hitting MongoDB on every authenticated API call
const _userCache = new Map();
const USER_CACHE_MAX = 100;
const USER_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function getCachedUser(userId) {
  const entry = _userCache.get(userId);
  if (entry && Date.now() - entry.ts < USER_CACHE_TTL_MS) {
    return entry.user;
  }
  _userCache.delete(userId);
  return null;
}

function setCachedUser(userId, user) {
  // Evict oldest entry if cache is full (simple LRU via insertion order)
  if (_userCache.size >= USER_CACHE_MAX) {
    const firstKey = _userCache.keys().next().value;
    _userCache.delete(firstKey);
  }
  _userCache.set(userId, { user, ts: Date.now() });
}

const protect = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ success: false, error: 'Not authorized to access this resource' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'supersecretcyberwallxdrkey12345');

    // Check cache first before hitting DB
    let user = getCachedUser(decoded.id);
    if (!user) {
      // Only fetch the fields needed for authorization — skip password, timestamps, etc.
      user = await User.findById(decoded.id).select('_id username email role').lean();
      if (user) {
        setCachedUser(decoded.id, user);
      }
    }

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Normalize lean document _id to id for compatibility
    req.user = { ...user, id: user._id.toString() };
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Token is invalid or expired' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: `User role '${req.user ? req.user.role : 'none'}' is not authorized to perform this action`
      });
    }
    next();
  };
};

module.exports = { protect, authorize };
