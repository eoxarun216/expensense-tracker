const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');
const User = require('../models/User');

// ============= CONSTANTS =============

const TOKEN_TYPES = {
  ACCESS: 'access',
  REFRESH: 'refresh',
};

const AUTH_ERRORS = {
  NO_TOKEN: 'No token provided',
  INVALID_FORMAT: 'Invalid token format',
  INVALID_TOKEN: 'Token is not valid',
  EXPIRED_TOKEN: 'Token has expired',
  USER_NOT_FOUND: 'User not found',
  ACCOUNT_SUSPENDED: 'Account is suspended',
  ACCOUNT_DELETED: 'Account has been deleted',
  INSUFFICIENT_PERMISSIONS: 'Insufficient permissions',
  INVALID_ROLE: 'Invalid user role',
};

// ============= HELPER FUNCTIONS =============

/**
 * Extract token from Authorization header, body, or cookies
 */
const extractToken = (req) => {
  // Prefer Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  // Fallback to body (useful for refresh endpoints)
  if (req.body && req.body.refreshToken) {
    return req.body.refreshToken;
  }

  // Fallback to cookie (if you store refresh token in cookie)
  if (req.cookies && req.cookies.refreshToken) {
    return req.cookies.refreshToken;
  }

  return null;
};

/**
 * Verify JWT token and optionally assert token type
 */
const verifyToken = (token, secret = process.env.JWT_SECRET, expectedType = null) => {
  try {
    const decoded = jwt.verify(token, secret);
    if (expectedType && decoded.type && decoded.type !== expectedType) {
      throw new Error('Token type mismatch');
    }
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error(AUTH_ERRORS.EXPIRED_TOKEN);
    }
    if (error.name === 'JsonWebTokenError') {
      throw new Error(AUTH_ERRORS.INVALID_TOKEN);
    }
    // pass through other errors (e.g., type mismatch)
    throw error;
  }
};

/**
 * Generate new tokens (access + refresh), tokens include type in payload
 */
const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { id: userId, type: TOKEN_TYPES.ACCESS },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
  );

  const refreshToken = jwt.sign(
    { id: userId, type: TOKEN_TYPES.REFRESH },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d' }
  );

  return { accessToken, refreshToken };
};

// ============= MIDDLEWARE FUNCTIONS =============

/**
 * @middleware protect
 * @desc      Verify access token and attach user to request
 * @access    Private
 */
exports.protect = async (req, res, next) => {
  try {
    const token = extractToken(req);

    if (!token) {
      logger.warn('Protect: No token provided', { ip: req.ip, path: req.path });
      return res.status(401).json({ success: false, message: AUTH_ERRORS.NO_TOKEN, code: 'NO_TOKEN' });
    }

    let decoded;
    try {
      // Ensure this is an access token
      decoded = verifyToken(token, process.env.JWT_SECRET, TOKEN_TYPES.ACCESS);
    } catch (error) {
      logger.warn('Protect: Invalid token', { error: error.message, ip: req.ip, path: req.path });
      return res.status(401).json({
        success: false,
        message: error.message,
        code: error.message === AUTH_ERRORS.EXPIRED_TOKEN ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN',
      });
    }

    let user;
    try {
      user = await User.findById(decoded.id).select('-password -refreshTokens -twoFactorSecret');

      if (!user) {
        logger.warn('Protect: User not found', { userId: decoded.id, ip: req.ip });
        return res.status(401).json({ success: false, message: AUTH_ERRORS.USER_NOT_FOUND, code: 'USER_NOT_FOUND' });
      }

      if (user.status === 'suspended') {
        logger.warn('Protect: Account suspended', { userId: user._id, ip: req.ip });
        return res.status(403).json({ success: false, message: AUTH_ERRORS.ACCOUNT_SUSPENDED, code: 'ACCOUNT_SUSPENDED' });
      }

      if (user.status === 'deleted') {
        logger.warn('Protect: Account deleted', { userId: user._id, ip: req.ip });
        return res.status(403).json({ success: false, message: AUTH_ERRORS.ACCOUNT_DELETED, code: 'ACCOUNT_DELETED' });
      }

      if (user.accountLocked && user.lockUntil && new Date() < user.lockUntil) {
        logger.warn('Protect: Account locked', { userId: user._id, ip: req.ip, lockUntil: user.lockUntil });
        return res.status(423).json({
          success: false,
          message: 'Account is locked. Please try again later.',
          code: 'ACCOUNT_LOCKED',
          lockUntil: user.lockUntil,
        });
      }

      if (process.env.REQUIRE_EMAIL_VERIFICATION === 'true' && !user.isEmailVerified) {
        logger.warn('Protect: Email not verified', { userId: user._id, ip: req.ip });
        return res.status(403).json({
          success: false,
          message: 'Please verify your email to access this resource',
          code: 'EMAIL_NOT_VERIFIED',
        });
      }
    } catch (error) {
      logger.error('Protect: Database error', { error: error.message, userId: decoded.id });
      return res.status(500).json({ success: false, message: 'Error retrieving user information', code: 'DB_ERROR' });
    }

    req.user = user;
    req.token = token;

    // Update last activity asynchronously (no await)
    user.lastActivityAt = new Date();
    user.save().catch(err => logger.error('Failed to update lastActivityAt', { error: err.message }));

    logger.debug('Protect: User authenticated successfully', { userId: user._id, email: user.email });

    next();
  } catch (error) {
    logger.error('Protect middleware error', { error: error.message, stack: error.stack, ip: req.ip });
    res.status(500).json({ success: false, message: 'Authentication error', code: 'AUTH_ERROR' });
  }
};

/**
 * @middleware authorize
 * @desc      Check if user has required role
 * @param     {...string} allowedRoles - Roles allowed to access
 * @access    Private
 */
exports.authorize = (...allowedRoles) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({ success: false, message: AUTH_ERRORS.NO_TOKEN, code: 'NO_TOKEN' });
      }

      if (!allowedRoles.includes(req.user.role)) {
        logger.warn('Authorize: Insufficient permissions', {
          userId: req.user._id,
          userRole: req.user.role,
          requiredRoles: allowedRoles,
          path: req.path,
        });
        return res.status(403).json({
          success: false,
          message: AUTH_ERRORS.INSUFFICIENT_PERMISSIONS,
          code: 'INSUFFICIENT_PERMISSIONS',
          requiredRoles: allowedRoles,
          userRole: req.user.role,
        });
      }

      logger.debug('Authorize: User authorized', { userId: req.user._id, role: req.user.role });

      next();
    } catch (error) {
      logger.error('Authorize middleware error', { error: error.message, userId: req.user?._id });
      res.status(500).json({ success: false, message: 'Authorization error', code: 'AUTHZ_ERROR' });
    }
  };
};

/**
 * @middleware optionalAuth
 * @desc      Attach user if a valid access token is provided, but don't require it
 * @access    Public/Private
 */
exports.optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      req.user = null;
      return next();
    }

    if (!authHeader.startsWith('Bearer ')) {
      req.user = null;
      return next();
    }

    const token = authHeader.slice(7);
    try {
      // Only accept access tokens here
      const decoded = verifyToken(token, process.env.JWT_SECRET, TOKEN_TYPES.ACCESS);
      const user = await User.findById(decoded.id).select('-password -refreshTokens -twoFactorSecret');

      if (user && user.status === 'active') {
        req.user = user;
        req.token = token;
        user.lastActivityAt = new Date();
        user.save().catch(err => logger.error('Failed to update lastActivityAt', { error: err.message }));
      }
    } catch (error) {
      logger.debug('OptionalAuth: Invalid token (ignored)', { error: error.message });
      req.user = null;
    }

    next();
  } catch (error) {
    logger.error('OptionalAuth middleware error', { error: error.message });
    req.user = null;
    next();
  }
};

/**
 * @middleware refreshAuth
 * @desc      Verify refresh token and issue new access token (returns tokens)
 * @access    Public
 *
 * Note: This middleware returns JSON (response), because refresh endpoints often do this.
 * If you prefer it to attach tokens to req and call next(), change accordingly.
 */
exports.refreshAuth = async (req, res, next) => {
  try {
    // Accept refresh token from Authorization header, body.refreshToken, or cookie
    const token = extractToken(req);

    if (!token) {
      logger.warn('RefreshAuth: No token provided', { ip: req.ip });
      return res.status(401).json({ success: false, message: AUTH_ERRORS.NO_TOKEN, code: 'NO_TOKEN' });
    }

    let decoded;
    try {
      // Ensure token is a refresh token
      decoded = verifyToken(token, process.env.REFRESH_TOKEN_SECRET, TOKEN_TYPES.REFRESH);
    } catch (error) {
      logger.warn('RefreshAuth: Invalid refresh token', { error: error.message });
      return res.status(401).json({ success: false, message: 'Invalid refresh token', code: 'INVALID_REFRESH_TOKEN' });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      logger.warn('RefreshAuth: User not found', { userId: decoded.id });
      return res.status(404).json({ success: false, message: AUTH_ERRORS.USER_NOT_FOUND, code: 'USER_NOT_FOUND' });
    }

    // Support both string arrays and object arrays like [{ token: '...' }]
    const hasToken = Array.isArray(user.refreshTokens) && user.refreshTokens.some(rt => {
      if (!rt) return false;
      if (typeof rt === 'string') return rt === token;
      if (rt.token) return rt.token === token;
      return false;
    });

    if (!hasToken) {
      logger.warn('RefreshAuth: Token not found in user', { userId: user._id });
      return res.status(401).json({ success: false, message: 'Refresh token not found', code: 'TOKEN_NOT_FOUND' });
    }

    // Generate fresh tokens
    const { accessToken, refreshToken } = generateTokens(user._id);

    // Save new refresh token and remove old one (assumes model methods exist)
    try {
      // attempt to remove old token if model has method
      if (typeof user.removeRefreshToken === 'function') {
        await user.removeRefreshToken(token);
      } else {
        // fallback: filter array (best-effort)
        user.refreshTokens = (user.refreshTokens || []).filter(rt => {
          if (!rt) return false;
          if (typeof rt === 'string') return rt !== token;
          if (rt.token) return rt.token !== token;
          return true;
        });
      }

      if (typeof user.addRefreshToken === 'function') {
        await user.addRefreshToken(refreshToken);
      } else {
        user.refreshTokens = user.refreshTokens || [];
        user.refreshTokens.push(refreshToken);
      }

      await user.save();
    } catch (err) {
      logger.error('RefreshAuth: Failed to rotate refresh tokens', { error: err.message, userId: user._id });
      // continue — still return tokens (but ideally you want rotation to succeed)
    }

    logger.info('RefreshAuth: New tokens generated', { userId: user._id });

    return res.json({
      success: true,
      message: 'Token refreshed successfully',
      accessToken,
      refreshToken,
    });
  } catch (error) {
    logger.error('RefreshAuth middleware error', { error: error.message });
    return res.status(500).json({ success: false, message: 'Token refresh error', code: 'REFRESH_ERROR' });
  }
};

/**
 * @middleware rateLimitByUser
 * @desc      Rate limit by user ID (in-memory)
 * @access    Private
 */
exports.rateLimitByUser = (maxRequests = 100, windowMs = 60000) => {
  const userRequestCounts = new Map();

  return (req, res, next) => {
    if (!req.user) return next();

    const userId = req.user._id.toString();
    const now = Date.now();

    if (!userRequestCounts.has(userId)) userRequestCounts.set(userId, []);

    const requests = userRequestCounts.get(userId);
    const validRequests = requests.filter(time => now - time < windowMs);
    userRequestCounts.set(userId, validRequests);

    if (validRequests.length >= maxRequests) {
      logger.warn('RateLimitByUser: Rate limit exceeded', { userId, requests: validRequests.length, max: maxRequests });
      return res.status(429).json({
        success: false,
        message: 'Too many requests',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil(windowMs / 1000),
      });
    }

    validRequests.push(now);
    next();
  };
};
