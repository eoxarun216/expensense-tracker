// middleware/auth.js - Simplified Version
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');
const User = require('../models/User');

// ============= MIDDLEWARE FUNCTIONS =============

/**
 * @middleware protect
 * @desc      Verify access token and attach user to request
 * @access    Private
 */
exports.protect = async (req, res, next) => {
  try {
    // 1. Extract token from Authorization header
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) {
      logger.warn('Protect: No token provided', { ip: req.ip, path: req.path });
      return res.status(401).json({ success: false, message: 'No token, authorization denied' });
    }

    // 2. Verify the token
    let decoded;
    try {
      // Use the standard JWT_SECRET for verification
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      logger.warn('Protect: Invalid token', { error: error.message, ip: req.ip, path: req.path });
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ success: false, message: 'Token is expired' });
      }
      // General invalid token error
      return res.status(401).json({ success: false, message: 'Token is not valid' });
    }

    // 3. Fetch user from database (excluding password)
    const user = await User.findById(decoded.id).select('-password'); // Exclude password from query result

    if (!user) {
      logger.warn('Protect: User not found', { userId: decoded.id, ip: req.ip });
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    // 4. Attach user object to request
    req.user = user;

    logger.debug('Protect: User authenticated successfully', { userId: user._id, email: user.email });

    // 5. Proceed to the next middleware/route handler
    next();
  } catch (error) {
    logger.error('Protect middleware error', { error: error.message, stack: error.stack, ip: req.ip });
    res.status(500).json({ success: false, message: 'Server error during authentication' });
  }
};

// Removed authorize, optionalAuth, refreshAuth, rateLimitByUser middlewares