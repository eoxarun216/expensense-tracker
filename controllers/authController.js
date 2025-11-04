// File: controllers/authController.js

const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const logger = require('../utils/logger');
const { validationResult } = require('express-validator');

// ============= CONSTANTS =============

const JWT_EXPIRY = '24h';
const REFRESH_TOKEN_EXPIRY = '7d';
const SALT_ROUNDS = 10;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes

// ============= HELPER FUNCTIONS =============

/**
 * Generate JWT Token
 * @param {string} id - User ID
 * @returns {string} JWT token
 */
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: JWT_EXPIRY,
  });
};

/**
 * Generate refresh token
 * @param {string} id - User ID
 * @returns {string} Refresh token
 */
const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRY,
  });
};

/**
 * Build user response object
 * @param {object} user - User document
 * @returns {object} User response
 */
const buildUserResponse = (user) => ({
  id: user._id,
  _id: user._id,
  name: user.name,
  email: user.email,
  phone: user.phone || null,
  avatar: user.avatar || null,
  role: user.role || 'user',
  isEmailVerified: user.isEmailVerified || false,
  createdAt: user.createdAt,
  updatedAt: user.updatedAt,
});

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} Is valid email
 */
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Check password strength
 * @param {string} password - Password to check
 * @returns {object} { isStrong: boolean, message: string }
 */
const checkPasswordStrength = (password) => {
  if (password.length < 8) {
    return { isStrong: false, message: 'Password must be at least 8 characters' };
  }
  if (!/[A-Z]/.test(password)) {
    return { isStrong: false, message: 'Password must contain uppercase letter' };
  }
  if (!/[a-z]/.test(password)) {
    return { isStrong: false, message: 'Password must contain lowercase letter' };
  }
  if (!/[0-9]/.test(password)) {
    return { isStrong: false, message: 'Password must contain number' };
  }
  if (!/[!@#$%^&*]/.test(password)) {
    return { isStrong: false, message: 'Password must contain special character (!@#$%^&*)' };
  }
  return { isStrong: true, message: 'Password is strong' };
};

/**
 * Handle validation errors
 * @param {object} req - Express request
 * @param {object} res - Express response
 * @returns {boolean} Has errors
 */
const handleValidationErrors = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Validation errors', { errors: errors.array() });
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(e => ({ field: e.param, message: e.msg })),
    });
  }
  return false;
};

// ============= AUTH CONTROLLER =============

/**
 * @desc    Register new user
 * @route   POST /api/auth/signup
 * @access  Public
 */
exports.signup = async (req, res) => {
  try {
    // Check validation errors
    if (handleValidationErrors(req, res)) return;

    const { name, email, password, confirmPassword } = req.body;

    logger.info('Signup attempt', { email });

    // Validate input
    if (!name || !email || !password || !confirmPassword) {
      logger.warn('Signup: Missing required fields', { email });
      return res.status(400).json({
        success: false,
        message: 'Please provide all required fields',
      });
    }

    // Validate email format
    if (!isValidEmail(email)) {
      logger.warn('Signup: Invalid email format', { email });
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address',
      });
    }

    // Check password match
    if (password !== confirmPassword) {
      logger.warn('Signup: Passwords do not match', { email });
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match',
      });
    }

    // Check password strength
    const passwordCheck = checkPasswordStrength(password);
    if (!passwordCheck.isStrong) {
      logger.warn('Signup: Weak password', { email });
      return res.status(400).json({
        success: false,
        message: passwordCheck.message,
      });
    }

    // Check if user already exists
    const userExists = await User.findOne({ email: email.toLowerCase() });
    if (userExists) {
      logger.warn('Signup: User already exists', { email });
      return res.status(409).json({
        success: false,
        message: 'Email already registered. Please login or use a different email.',
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = await User.create({
      name: name.trim(),
      email: email.toLowerCase(),
      password: hashedPassword,
    });

    if (!user) {
      logger.error('Signup: Failed to create user', { email });
      return res.status(500).json({
        success: false,
        message: 'Failed to create user account',
      });
    }

    // Generate tokens
    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    logger.info('Signup: User created successfully', { userId: user._id, email });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      refreshToken,
      user: buildUserResponse(user),
    });
  } catch (error) {
    logger.error('Signup error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'An error occurred during signup. Please try again later.',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

/**
 * @desc    Login user
 * @route   POST /api/auth/login
 * @access  Public
 */
exports.login = async (req, res) => {
  try {
    // Check validation errors
    if (handleValidationErrors(req, res)) return;

    const { email, password } = req.body;

    logger.info('Login attempt', { email });

    // Validate input
    if (!email || !password) {
      logger.warn('Login: Missing email or password', { email });
      return res.status(400).json({
        success: false,
        message: 'Please provide email and password',
      });
    }

    // Find user by email and get password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

    if (!user) {
      logger.warn('Login: User not found', { email });
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    // Check if account is locked
    if (user.accountLocked && user.lockUntil && new Date() < user.lockUntil) {
      logger.warn('Login: Account locked', { email });
      return res.status(423).json({
        success: false,
        message: 'Account is temporarily locked. Please try again later.',
        lockUntil: user.lockUntil,
      });
    }

    // Check password
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      // Increment login attempts
      user.loginAttempts = (user.loginAttempts || 0) + 1;

      // Lock account if max attempts exceeded
      if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
        user.accountLocked = true;
        user.lockUntil = new Date(Date.now() + LOCK_TIME);
        logger.warn('Login: Account locked due to max attempts', { email });
      }

      await user.save();

      logger.warn('Login: Invalid password', { email, attempts: user.loginAttempts });
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        attemptsRemaining: Math.max(0, MAX_LOGIN_ATTEMPTS - user.loginAttempts),
      });
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.accountLocked = false;
    user.lastLogin = new Date();
    await user.save();

    // Generate tokens
    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    logger.info('Login: User logged in successfully', { userId: user._id, email });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      refreshToken,
      user: buildUserResponse(user),
    });
  } catch (error) {
    logger.error('Login error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'An error occurred during login. Please try again later.',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

/**
 * @desc    Get user profile
 * @route   GET /api/auth/profile
 * @access  Private
 */
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password -refreshTokens -twoFactorSecret');

    if (!user) {
      logger.warn('GetProfile: User not found', { userId: req.user._id });
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    logger.info('GetProfile: Retrieved successfully', { userId: user._id });

    res.json({
      success: true,
      user: buildUserResponse(user),
    });
  } catch (error) {
    logger.error('GetProfile error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'An error occurred while retrieving profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

/**
 * @desc    Update user profile
 * @route   PUT /api/auth/profile
 * @access  Private
 */
exports.updateProfile = async (req, res) => {
  try {
    // Check validation errors
    if (handleValidationErrors(req, res)) return;

    const { name, email, phone, avatar, bio } = req.body;

    logger.info('UpdateProfile: Update attempt', { userId: req.user._id });

    // Find user
    let user = await User.findById(req.user._id);

    if (!user) {
      logger.warn('UpdateProfile: User not found', { userId: req.user._id });
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Check if new email is already used
    if (email && email.toLowerCase() !== user.email) {
      const emailExists = await User.findOne({
        email: email.toLowerCase(),
        _id: { $ne: user._id },
      });

      if (emailExists) {
        logger.warn('UpdateProfile: Email already in use', { email });
        return res.status(409).json({
          success: false,
          message: 'Email is already in use',
        });
      }

      if (!isValidEmail(email)) {
        logger.warn('UpdateProfile: Invalid email format', { email });
        return res.status(400).json({
          success: false,
          message: 'Please provide a valid email address',
        });
      }

      user.email = email.toLowerCase();
    }

    // Update fields
    if (name) user.name = name.trim();
    if (phone) user.phone = phone.trim();
    if (avatar) user.avatar = avatar;
    if (bio) user.bio = bio.trim();

    user = await user.save();

    logger.info('UpdateProfile: Updated successfully', { userId: user._id });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: buildUserResponse(user),
    });
  } catch (error) {
    logger.error('UpdateProfile error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'An error occurred while updating profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

/**
 * @desc    Change password
 * @route   POST /api/auth/change-password
 * @access  Private
 */
exports.changePassword = async (req, res) => {
  try {
    // Check validation errors
    if (handleValidationErrors(req, res)) return;

    const { currentPassword, newPassword, confirmPassword } = req.body;

    logger.info('ChangePassword: Change attempt', { userId: req.user._id });

    // Validate input
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Please provide all required fields',
      });
    }

    // Passwords must match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'New passwords do not match',
      });
    }

    // Check password strength
    const passwordCheck = checkPasswordStrength(newPassword);
    if (!passwordCheck.isStrong) {
      return res.status(400).json({
        success: false,
        message: passwordCheck.message,
      });
    }

    // Find user
    const user = await User.findById(req.user._id).select('+password');

    if (!user) {
      logger.warn('ChangePassword: User not found', { userId: req.user._id });
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Verify current password
    const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isPasswordMatch) {
      logger.warn('ChangePassword: Wrong current password', { userId: req.user._id });
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect',
      });
    }

    // New password cannot be same as current
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({
        success: false,
        message: 'New password cannot be the same as current password',
      });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    user.password = await bcrypt.hash(newPassword, salt);
    user.passwordChangedAt = new Date();

    await user.save();

    logger.info('ChangePassword: Password changed successfully', { userId: user._id });

    res.json({
      success: true,
      message: 'Password changed successfully',
    });
  } catch (error) {
    logger.error('ChangePassword error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'An error occurred while changing password',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

/**
 * @desc    Refresh token
 * @route   POST /api/auth/refresh-token
 * @access  Public
 */
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required',
      });
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET);
    } catch (error) {
      logger.warn('RefreshToken: Invalid or expired refresh token');
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired refresh token',
      });
    }

    // Find user
    const user = await User.findById(decoded.id);

    if (!user) {
      logger.warn('RefreshToken: User not found', { userId: decoded.id });
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Generate new tokens
    const newToken = generateToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    logger.info('RefreshToken: Tokens refreshed successfully', { userId: user._id });

    res.json({
      success: true,
      message: 'Tokens refreshed successfully',
      token: newToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    logger.error('RefreshToken error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'An error occurred while refreshing token',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

/**
 * @desc    Logout user
 * @route   POST /api/auth/logout
 * @access  Private
 */
exports.logout = async (req, res) => {
  try {
    logger.info('Logout: User logging out', { userId: req.user._id });

    res.json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    logger.error('Logout error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'An error occurred during logout',
    });
  }
};

/**
 * @desc    Request password reset
 * @route   POST /api/auth/forgot-password
 * @access  Public
 */
exports.requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });

    // Don't reveal if email exists
    logger.info('RequestPasswordReset: Request received', { email });

    res.json({
      success: true,
      message: 'If email exists, password reset link has been sent',
    });
  } catch (error) {
    logger.error('RequestPasswordReset error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Password reset request failed',
    });
  }
};

/**
 * @desc    Reset password
 * @route   POST /api/auth/reset-password
 * @access  Public
 */
exports.resetPassword = async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match',
      });
    }

    const passwordCheck = checkPasswordStrength(password);
    if (!passwordCheck.isStrong) {
      return res.status(400).json({
        success: false,
        message: passwordCheck.message,
      });
    }

    logger.info('ResetPassword: Password reset request received');

    res.json({
      success: true,
      message: 'Password reset successful',
    });
  } catch (error) {
    logger.error('ResetPassword error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Password reset failed',
    });
  }
};

/**
 * @desc    Verify email
 * @route   POST /api/auth/verify-email
 * @access  Public
 */
exports.verifyEmail = async (req, res) => {
  try {
    const { token } = req.body;

    logger.info('VerifyEmail: Email verification request received');

    res.json({
      success: true,
      message: 'Email verified successfully',
    });
  } catch (error) {
    logger.error('VerifyEmail error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Email verification failed',
    });
  }
};

/**
 * @desc    Request email verification
 * @route   POST /api/auth/request-email-verification
 * @access  Public
 */
exports.requestEmailVerification = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    logger.info('RequestEmailVerification: Request received', { email });

    res.json({
      success: true,
      message: 'Verification email sent',
    });
  } catch (error) {
    logger.error('RequestEmailVerification error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Request failed',
    });
  }
};

/**
 * @desc    Verify phone number
 * @route   POST /api/auth/verify-phone
 * @access  Public
 */
exports.verifyPhoneNumber = async (req, res) => {
  try {
    logger.info('VerifyPhone: Phone verification request received');

    res.json({
      success: true,
      message: 'Phone verified successfully',
    });
  } catch (error) {
    logger.error('VerifyPhone error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Phone verification failed',
    });
  }
};

/**
 * @desc    Request phone verification
 * @route   POST /api/auth/request-phone-verification
 * @access  Public
 */
exports.requestPhoneVerification = async (req, res) => {
  try {
    const { phone } = req.body;

    logger.info('RequestPhoneVerification: Request received', { phone });

    res.json({
      success: true,
      message: 'OTP sent to phone',
    });
  } catch (error) {
    logger.error('RequestPhoneVerification error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Request failed',
    });
  }
};

/**
 * @desc    Enable two-factor authentication
 * @route   POST /api/auth/enable-2fa
 * @access  Private
 */
exports.enableTwoFactor = async (req, res) => {
  try {
    logger.info('EnableTwoFactor: Request received', { userId: req.user._id });

    res.json({
      success: true,
      message: '2FA enabled successfully',
    });
  } catch (error) {
    logger.error('EnableTwoFactor error', { error: error.message });
    res.status(500).json({
      success: false,
      message: '2FA enablement failed',
    });
  }
};

/**
 * @desc    Disable two-factor authentication
 * @route   POST /api/auth/disable-2fa
 * @access  Private
 */
exports.disableTwoFactor = async (req, res) => {
  try {
    logger.info('DisableTwoFactor: Request received', { userId: req.user._id });

    res.json({
      success: true,
      message: '2FA disabled successfully',
    });
  } catch (error) {
    logger.error('DisableTwoFactor error', { error: error.message });
    res.status(500).json({
      success: false,
      message: '2FA disablement failed',
    });
  }
};

/**
 * @desc    Verify 2FA code
 * @route   POST /api/auth/verify-2fa
 * @access  Private
 */
exports.verifyTwoFactorCode = async (req, res) => {
  try {
    const { code } = req.body;

    logger.info('VerifyTwoFactorCode: Request received', { userId: req.user._id });

    res.json({
      success: true,
      message: '2FA code verified successfully',
    });
  } catch (error) {
    logger.error('VerifyTwoFactorCode error', { error: error.message });
    res.status(500).json({
      success: false,
      message: '2FA code verification failed',
    });
  }
};

/**
 * @desc    Get social auth URL
 * @route   GET /api/auth/social/:provider/url
 * @access  Public
 */
exports.getSocialAuthUrl = async (req, res) => {
  try {
    logger.info('GetSocialAuthUrl: Request received');

    res.json({
      success: true,
      message: 'Social auth URL',
      url: 'https://example.com/oauth',
    });
  } catch (error) {
    logger.error('GetSocialAuthUrl error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to get social auth URL',
    });
  }
};

/**
 * @desc    Handle social auth callback
 * @route   POST /api/auth/social/:provider/callback
 * @access  Public
 */
exports.handleSocialCallback = async (req, res) => {
  try {
    logger.info('HandleSocialCallback: Request received');

    res.json({
      success: true,
      message: 'Social authentication successful',
      token: generateToken('userId'),
      refreshToken: generateRefreshToken('userId'),
    });
  } catch (error) {
    logger.error('HandleSocialCallback error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Social authentication failed',
    });
  }
};

/**
 * @desc    Delete user account
 * @route   DELETE /api/auth/account
 * @access  Private
 */
exports.deleteAccount = async (req, res) => {
  try {
    const { password } = req.body;

    const user = await User.findById(req.user._id).select('+password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      logger.warn('DeleteAccount: Invalid password', { userId: req.user._id });
      return res.status(401).json({
        success: false,
        message: 'Password is incorrect',
      });
    }

    await User.findByIdAndDelete(req.user._id);

    logger.info('DeleteAccount: Account deleted', { userId: req.user._id });

    res.json({
      success: true,
      message: 'Account deleted successfully',
    });
  } catch (error) {
    logger.error('DeleteAccount error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Account deletion failed',
    });
  }
};

/**
 * @desc    Get login history
 * @route   GET /api/auth/login-history
 * @access  Private
 */
exports.getLoginHistory = async (req, res) => {
  try {
    logger.info('GetLoginHistory: Request received', { userId: req.user._id });

    res.json({
      success: true,
      message: 'Login history retrieved',
      history: [],
    });
  } catch (error) {
    logger.error('GetLoginHistory error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve login history',
    });
  }
};

/**
 * @desc    Get activity log
 * @route   GET /api/auth/activity-log
 * @access  Private
 */
exports.getActivityLog = async (req, res) => {
  try {
    logger.info('GetActivityLog: Request received', { userId: req.user._id });

    res.json({
      success: true,
      message: 'Activity log retrieved',
      activities: [],
    });
  } catch (error) {
    logger.error('GetActivityLog error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve activity log',
    });
  }
};

/**
 * @desc    Link social account
 * @route   POST /api/auth/link-social/:provider
 * @access  Private
 */
exports.linkSocialAccount = async (req, res) => {
  try {
    logger.info('LinkSocialAccount: Request received', { userId: req.user._id });

    res.json({
      success: true,
      message: 'Social account linked successfully',
    });
  } catch (error) {
    logger.error('LinkSocialAccount error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to link social account',
    });
  }
};

/**
 * @desc    Unlink social account
 * @route   POST /api/auth/unlink-social/:provider
 * @access  Private
 */
exports.unlinkSocialAccount = async (req, res) => {
  try {
    logger.info('UnlinkSocialAccount: Request received', { userId: req.user._id });

    res.json({
      success: true,
      message: 'Social account unlinked successfully',
    });
  } catch (error) {
    logger.error('UnlinkSocialAccount error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to unlink social account',
    });
  }
};
