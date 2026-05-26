const jwt = require('jsonwebtoken');

const protect = (req, res, next) => {
  // 1. Check Gateway Headers first
  const gatewayUserId = req.headers['x-user-id'];
  const gatewayUserRole = req.headers['x-user-role'];
  const gatewayUserUsername = req.headers['x-user-username'];
  const gatewayUserEmail = req.headers['x-user-email'];

  if (gatewayUserId) {
    req.user = {
      id: gatewayUserId,
      role: gatewayUserRole || 'analyst',
      username: gatewayUserUsername || '',
      email: gatewayUserEmail || ''
    };
    return next();
  }

  // 2. Fallback to direct JWT validation if not routed through Gateway
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ success: false, error: 'Not authorized to access this resource' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'supersecretcyberwallxdrkey12345');
    req.user = {
      id: decoded.id,
      role: decoded.role || 'analyst' // Role can be encoded in token or decoded/fetched if needed.
    };
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Token is invalid or expired' });
  }
};

const ROLES = {
  SUPERADMIN: 'superadmin',
  ADMIN: 'admin',
  ANALYST: 'analyst',
  VIEWER: 'viewer'
};

const ROLE_HIERARCHY = {
  [ROLES.SUPERADMIN]: [ROLES.SUPERADMIN, ROLES.ADMIN, ROLES.ANALYST, ROLES.VIEWER],
  [ROLES.ADMIN]: [ROLES.ADMIN, ROLES.ANALYST, ROLES.VIEWER],
  [ROLES.ANALYST]: [ROLES.ANALYST, ROLES.VIEWER],
  [ROLES.VIEWER]: [ROLES.VIEWER]
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Not authorized to access this resource' });
    }
    const userRole = req.user.role || ROLES.VIEWER;
    const allowed = ROLE_HIERARCHY[userRole] || [userRole];
    const isAuthorized = roles.some(role => allowed.includes(role));

    if (!isAuthorized) {
      return res.status(403).json({
        success: false,
        error: `User role '${userRole}' is not authorized to perform this action`
      });
    }
    next();
  };
};

module.exports = { protect, authorize, ROLES };
