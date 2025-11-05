// File: routes/authRoutes.js

const express = require('express');
const router = express.Router();
const { body, query } = require('express-validator');
const logger = require('../utils/logger');

// Controllers (email + password flows only)
const {
  signup,
  login,
  logout,
  getProfile,
  updateProfile,
  changePassword,
  refreshToken,
  requestPasswordReset,
  resetPassword,
  verifyEmail,
  requestEmailVerification,
  deleteAccount,
  getLoginHistory,
  getActivityLog,
} = require('../controllers/authController');

// Middleware
const { protect, authorize } = require('../middleware/auth');
const rateLimiter = require('../middleware/rateLimiter');
const validateRequest = require('../middleware/validateRequest');

// ============= VALIDATION SCHEMAS =============

const signupValidation = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('Name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters'),
  body('email')
    .trim()
    .toLowerCase()
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*]/)
    .withMessage('Password must contain at least one special character (!@#$%^&*)')
    .custom((value, { req }) => {
      if (value !== req.body.confirmPassword) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
  body('confirmPassword')
    .notEmpty()
    .withMessage('Please confirm your password'),
];

const loginValidation = [
  body('email')
    .trim()
    .toLowerCase()
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Please provide a password'),
];

const updateProfileValidation = [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters'),
  body('phone')
    .optional()
    .trim()
    .isMobilePhone('any')
    .withMessage('Please provide a valid phone number'),
  body('bio')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Bio cannot exceed 500 characters'),
  body('avatar')
    .optional()
    .isURL()
    .withMessage('Please provide a valid avatar URL'),
];

const changePasswordValidation = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*]/)
    .withMessage('Password must contain at least one special character'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
];

const emailValidation = [
  body('email')
    .trim()
    .toLowerCase()
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
];

const passwordResetValidation = [
  body('token')
    .notEmpty()
    .withMessage('Reset token is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
];

// ============= PUBLIC ROUTES =============

router.post(
  '/signup',
  rateLimiter.signup,
  signupValidation,
  validateRequest,
  signup
);

router.post(
  '/login',
  rateLimiter.login,
  loginValidation,
  validateRequest,
  login
);

router.post(
  '/refresh-token',
  rateLimiter.general,
  [
    body('refreshToken')
      .notEmpty()
      .withMessage('Refresh token is required'),
  ],
  validateRequest,
  refreshToken
);

router.post(
  '/forgot-password',
  rateLimiter.passwordReset,
  emailValidation,
  validateRequest,
  requestPasswordReset
);

router.post(
  '/reset-password',
  rateLimiter.passwordReset,
  passwordResetValidation,
  validateRequest,
  resetPassword
);

router.post(
  '/verify-email',
  rateLimiter.verification,
  [
    body('token')
      .notEmpty()
      .withMessage('Verification token is required'),
  ],
  validateRequest,
  verifyEmail
);

router.post(
  '/request-email-verification',
  rateLimiter.verification,
  emailValidation,
  validateRequest,
  requestEmailVerification
);

// ============= PROTECTED ROUTES =============

/**
 * /me returns the same as getProfile; kept for convenience
 */
router.get('/me', protect, getProfile);

router.get('/profile', protect, getProfile);

router.put(
  '/profile',
  protect,
  updateProfileValidation,
  validateRequest,
  updateProfile
);

router.post(
  '/change-password',
  protect,
  rateLimiter.general,
  changePasswordValidation,
  validateRequest,
  changePassword
);

router.post('/logout', protect, rateLimiter.general, logout);

router.post('/logout-all', protect, rateLimiter.general, async (req, res) => {
  try {
    const User = require('../models/User');
    await User.findByIdAndUpdate(req.user._id, { $set: { refreshTokens: [] } });

    logger.info('LogoutAll: All sessions terminated', { userId: req.user._id });

    res.json({ success: true, message: 'Logged out from all devices' });
  } catch (error) {
    logger.error('LogoutAll error', { error: error.message });
    res.status(500).json({ success: false, message: 'Failed to logout from all devices' });
  }
});

router.get('/login-history', protect, getLoginHistory);

router.get('/activity-log', protect, getActivityLog);

router.delete(
  '/account',
  protect,
  rateLimiter.general,
  [
    body('password')
      .notEmpty()
      .withMessage('Password is required to delete account'),
    body('confirmation')
      .equals('DELETE')
      .withMessage('Please confirm account deletion'),
  ],
  validateRequest,
  deleteAccount
);

router.put(
  '/preferences',
  protect,
  rateLimiter.general,
  [
    body('preferences')
      .isObject()
      .withMessage('Preferences must be an object'),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const User = require('../models/User');
      const user = await User.findById(req.user._id);

      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }

      await user.updatePreferences(req.body.preferences);

      logger.info('PreferencesUpdated', { userId: user._id });

      res.json({ success: true, message: 'Preferences updated successfully', preferences: user.preferences });
    } catch (error) {
      logger.error('UpdatePreferences error', { error: error.message });
      res.status(500).json({ success: false, message: 'Failed to update preferences' });
    }
  }
);

router.put(
  '/subscription',
  protect,
  authorize('admin'),
  rateLimiter.general,
  async (req, res) => {
    try {
      const User = require('../models/User');
      const user = await User.findById(req.user._id);

      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }

      await user.updateSubscription(req.body.subscription);

      logger.info('SubscriptionUpdated', { userId: user._id });

      res.json({ success: true, message: 'Subscription updated successfully', subscription: user.subscription });
    } catch (error) {
      logger.error('UpdateSubscription error', { error: error.message });
      res.status(500).json({ success: false, message: 'Failed to update subscription' });
    }
  }
);

// ============= ERROR HANDLING MIDDLEWARE =============

router.use((err, req, res, next) => {
  logger.error('Auth route error', { error: err.message });
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'An error occurred',
    error: process.env.NODE_ENV === 'development' ? err : undefined,
  });
});

module.exports = router;
