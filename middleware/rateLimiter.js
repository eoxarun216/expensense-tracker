// File: middleware/rateLimiter.js

const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');

// ============= RATE LIMITERS =============

/**
 * General API rate limiter
 */
const general = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development',
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', {
      ip: req.ip,
      path: req.path,
    });
    res.status(429).json({
      success: false,
      message: 'Too many requests, please try again later',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: req.rateLimit.resetTime,
    });
  },
});

/**
 * Authentication rate limiter - stricter
 */
const signup = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 requests per hour
  message: 'Too many signup attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development',
  handler: (req, res) => {
    logger.warn('Signup rate limit exceeded', {
      ip: req.ip,
      email: req.body?.email,
    });
    res.status(429).json({
      success: false,
      message: 'Too many signup attempts, please try again later',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: req.rateLimit.resetTime,
    });
  },
});

/**
 * Login rate limiter
 */
const login = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per 15 minutes
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development',
  handler: (req, res) => {
    logger.warn('Login rate limit exceeded', {
      ip: req.ip,
      email: req.body?.email,
    });
    res.status(429).json({
      success: false,
      message: 'Too many login attempts, please try again later',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: req.rateLimit.resetTime,
    });
  },
});

/**
 * Password reset rate limiter
 */
const passwordReset = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 requests per hour
  message: 'Too many password reset attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development',
  handler: (req, res) => {
    logger.warn('Password reset rate limit exceeded', {
      ip: req.ip,
    });
    res.status(429).json({
      success: false,
      message: 'Too many password reset attempts, please try again later',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: req.rateLimit.resetTime,
    });
  },
});

/**
 * Email/Phone verification rate limiter
 */
const verification = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 requests per hour
  message: 'Too many verification attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development',
  handler: (req, res) => {
    logger.warn('Verification rate limit exceeded', {
      ip: req.ip,
    });
    res.status(429).json({
      success: false,
      message: 'Too many verification attempts, please try again later',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: req.rateLimit.resetTime,
    });
  },
});

/**
 * Create/Delete operations rate limiter
 */
const createDelete = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 requests per minute
  message: 'Too many operations, please slow down',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development',
  handler: (req, res) => {
    logger.warn('Create/Delete rate limit exceeded', {
      ip: req.ip,
      path: req.path,
    });
    res.status(429).json({
      success: false,
      message: 'Too many operations, please slow down',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: req.rateLimit.resetTime,
    });
  },
});

/**
 * Search/Export operations rate limiter
 */
const search = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 requests per minute
  message: 'Too many search requests, please slow down',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development',
  handler: (req, res) => {
    logger.warn('Search rate limit exceeded', {
      ip: req.ip,
      query: req.query?.q,
    });
    res.status(429).json({
      success: false,
      message: 'Too many search requests, please slow down',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: req.rateLimit.resetTime,
    });
  },
});

/**
 * File upload rate limiter
 */
const upload = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 uploads per hour
  message: 'Too many file uploads, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development',
  handler: (req, res) => {
    logger.warn('Upload rate limit exceeded', {
      ip: req.ip,
    });
    res.status(429).json({
      success: false,
      message: 'Too many uploads, please try again later',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: req.rateLimit.resetTime,
    });
  },
});

// ============= EXPORT =============

module.exports = {
  general,
  signup,
  login,
  passwordReset,
  verification,
  createDelete,
  search,
  upload,
};
