// File: routes/authRoutes.js

const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const logger = require('../utils/logger');

// Controllers
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
  verifyPhoneNumber,
  requestPhoneVerification,
  enableTwoFactor,
  disableTwoFactor,
  verifyTwoFactorCode,
  getSocialAuthUrl,
  handleSocialCallback,
  deleteAccount,
  getLoginHistory,
  getActivityLog,
  linkSocialAccount,
  unlinkSocialAccount,
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

const twoFactorValidation = [
  body('code')
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('2FA code must be 6 digits'),
];

const phoneValidation = [
  body('phone')
    .trim()
    .isMobilePhone('any')
    .withMessage('Please provide a valid phone number'),
];

// ============= PUBLIC ROUTES =============

/**
 * @route   POST /api/auth/signup
 * @desc    Register a new user
 * @access  Public
 */
router.post(
  '/signup',
  rateLimiter.signup,
  signupValidation,
  validateRequest,
  signup
);

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post(
  '/login',
  rateLimiter.login,
  loginValidation,
  validateRequest,
  login
);

/**
 * @route   POST /api/auth/refresh-token
 * @desc    Refresh access token
 * @access  Public
 */
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

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 */
router.post(
  '/forgot-password',
  rateLimiter.passwordReset,
  emailValidation,
  validateRequest,
  requestPasswordReset
);

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post(
  '/reset-password',
  rateLimiter.passwordReset,
  passwordResetValidation,
  validateRequest,
  resetPassword
);

/**
 * @route   POST /api/auth/verify-email
 * @desc    Verify email with token
 * @access  Public
 */
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

/**
 * @route   POST /api/auth/request-email-verification
 * @desc    Request email verification
 * @access  Public
 */
router.post(
  '/request-email-verification',
  rateLimiter.verification,
  emailValidation,
  validateRequest,
  requestEmailVerification
);

/**
 * @route   POST /api/auth/request-phone-verification
 * @desc    Request phone verification
 * @access  Public
 */
router.post(
  '/request-phone-verification',
  rateLimiter.verification,
  phoneValidation,
  validateRequest,
  requestPhoneVerification
);

/**
 * @route   POST /api/auth/verify-phone
 * @desc    Verify phone with OTP
 * @access  Public
 */
router.post(
  '/verify-phone',
  rateLimiter.verification,
  [
    body('phone')
      .trim()
      .isMobilePhone('any')
      .withMessage('Please provide a valid phone number'),
    body('otp')
      .isLength({ min: 4, max: 6 })
      .isNumeric()
      .withMessage('OTP must be 4-6 digits'),
  ],
  validateRequest,
  verifyPhoneNumber
);

/**
 * @route   GET /api/auth/social/:provider/url
 * @desc    Get social authentication URL
 * @access  Public
 */
router.get(
  '/social/:provider/url',
  [
    body('redirectUrl')
      .isURL()
      .withMessage('Please provide a valid redirect URL'),
  ],
  getSocialAuthUrl
);

/**
 * @route   POST /api/auth/social/:provider/callback
 * @desc    Handle social authentication callback
 * @access  Public
 */
router.post(
  '/social/:provider/callback',
  rateLimiter.general,
  handleSocialCallback
);

// ============= PROTECTED ROUTES =============

/**
 * @route   GET /api/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/me', protect, async (req, res) => {
  try {
    logger.info('GetMe: Request received', { userId: req.user._id });

    const User = require('../models/User');
    const user = await User.findById(req.user._id).select('-password -refreshTokens -twoFactorSecret');

    if (!user) {
      logger.warn('GetMe: User not found', { userId: req.user._id });
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    logger.info('GetMe: Retrieved successfully', { userId: user._id });

    res.json({
      success: true,
      user: user.getProfile(),
    });
  } catch (error) {
    logger.error('GetMe error', { error: error.message, userId: req.user._id });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve user profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
});

/**
 * @route   GET /api/auth/profile
 * @desc    Get user profile
 * @access  Private
 */
router.get('/profile', protect, getProfile);

/**
 * @route   PUT /api/auth/profile
 * @desc    Update user profile
 * @access  Private
 */
router.put(
  '/profile',
  protect,
  updateProfileValidation,
  validateRequest,
  updateProfile
);

/**
 * @route   POST /api/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.post(
  '/change-password',
  protect,
  rateLimiter.general,
  changePasswordValidation,
  validateRequest,
  changePassword
);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post('/logout', protect, rateLimiter.general, logout);

/**
 * @route   POST /api/auth/logout-all
 * @desc    Logout from all devices
 * @access  Private
 */
router.post('/logout-all', protect, rateLimiter.general, async (req, res) => {
  try {
    const User = require('../models/User');
    await User.findByIdAndUpdate(req.user._id, {
      $set: { refreshTokens: [] },
    });

    logger.info('LogoutAll: All sessions terminated', { userId: req.user._id });

    res.json({
      success: true,
      message: 'Logged out from all devices',
    });
  } catch (error) {
    logger.error('LogoutAll error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to logout from all devices',
    });
  }
});

/**
 * @route   POST /api/auth/enable-2fa
 * @desc    Enable two-factor authentication
 * @access  Private
 */
router.post('/enable-2fa', protect, rateLimiter.general, enableTwoFactor);

/**
 * @route   POST /api/auth/disable-2fa
 * @desc    Disable two-factor authentication
 * @access  Private
 */
router.post(
  '/disable-2fa',
  protect,
  rateLimiter.general,
  twoFactorValidation,
  validateRequest,
  disableTwoFactor
);

/**
 * @route   POST /api/auth/verify-2fa
 * @desc    Verify 2FA code
 * @access  Private
 */
router.post(
  '/verify-2fa',
  protect,
  twoFactorValidation,
  validateRequest,
  verifyTwoFactorCode
);

/**
 * @route   GET /api/auth/login-history
 * @desc    Get user login history
 * @access  Private
 */
router.get('/login-history', protect, getLoginHistory);

/**
 * @route   GET /api/auth/activity-log
 * @desc    Get user activity log
 * @access  Private
 */
router.get('/activity-log', protect, getActivityLog);

/**
 * @route   POST /api/auth/link-social/:provider
 * @desc    Link social account to existing user
 * @access  Private
 */
router.post('/link-social/:provider', protect, rateLimiter.general, linkSocialAccount);

/**
 * @route   POST /api/auth/unlink-social/:provider
 * @desc    Unlink social account
 * @access  Private
 */
router.post('/unlink-social/:provider', protect, rateLimiter.general, unlinkSocialAccount);

/**
 * @route   DELETE /api/auth/account
 * @desc    Delete user account
 * @access  Private
 */
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

/**
 * @route   PUT /api/auth/preferences
 * @desc    Update user preferences
 * @access  Private
 */
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
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      await user.updatePreferences(req.body.preferences);

      logger.info('PreferencesUpdated', { userId: user._id });

      res.json({
        success: true,
        message: 'Preferences updated successfully',
        preferences: user.preferences,
      });
    } catch (error) {
      logger.error('UpdatePreferences error', { error: error.message });
      res.status(500).json({
        success: false,
        message: 'Failed to update preferences',
      });
    }
  }
);

/**
 * @route   PUT /api/auth/subscription
 * @desc    Update subscription
 * @access  Private
 */
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
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      await user.updateSubscription(req.body.subscription);

      logger.info('SubscriptionUpdated', { userId: user._id });

      res.json({
        success: true,
        message: 'Subscription updated successfully',
        subscription: user.subscription,
      });
    } catch (error) {
      logger.error('UpdateSubscription error', { error: error.message });
      res.status(500).json({
        success: false,
        message: 'Failed to update subscription',
      });
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
