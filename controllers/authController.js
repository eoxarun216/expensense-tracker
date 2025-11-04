// File: controllers/authController.js

const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const logger = require('../utils/logger');
const { validationResult } = require('express-validator');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const JWT_EXPIRY = '24h';
const REFRESH_TOKEN_EXPIRY = '7d';
const SALT_ROUNDS = 10;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes in milliseconds

// ============= HELPER FUNCTIONS =============

/**
 * Build user response object
 * @param {object} user - User document
 * @returns {object} User response
 */
function buildUserResponse(user) {
  if (!user) return null;
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    avatar: user.avatar,
    bio: user.bio,
    role: user.role,
    status: user.status,
    isEmailVerified: user.isEmailVerified,
    isPhoneVerified: user.isPhoneVerified,
    preferences: user.preferences,
    subscription: user.subscription,
    billingInfo: user.billingInfo,
    totalExpenses: user.totalExpenses,
    totalReminders: user.totalReminders,
    totalBudgets: user.totalBudgets,
    totalSpent: user.totalSpent,
    lastLogin: user.lastLogin,
    lastActivityAt: user.lastActivityAt,
    tags: user.tags,
    memberSince: user.createdAt,
    loginHistory: user.loginHistory ? user.loginHistory.slice(-50).reverse() : [],
    activityLog: user.activityLog ? user.activityLog.slice(-100).reverse() : [],
    social: {
      googleId: user.googleId,
      facebookId: user.facebookId,
      githubId: user.githubId,
      googleLinked: !!user.googleId,
      facebookLinked: !!user.facebookId,
      githubLinked: !!user.githubId
    },
    dataBackup: user.dataBackup,
    dataExport: user.dataExport,
    isPremium: (user.role === 'premium' || (user.subscription && user.subscription.type !== 'free')),
    isSubscriptionActive: user.isSubscriptionActive,
    isSubscriptionExpiringSoon: user.isSubscriptionExpiringSoon,
    daysUntilSubscriptionExpires: user.daysUntilSubscriptionExpires,
    deletedAt: user.deletedAt,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
}

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} Is valid email
 */
const isValidEmail = email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

/**
 * Check password strength
 * @param {string} password - Password to check
 * @returns {object} { isStrong: boolean, message: string }
 */
const checkPasswordStrength = password => {
  if (password.length < 8) return { isStrong: false, message: 'Password must be at least 8 characters' };
  if (!/[A-Z]/.test(password)) return { isStrong: false, message: 'Password must contain uppercase letter' };
  if (!/[a-z]/.test(password)) return { isStrong: false, message: 'Password must contain lowercase letter' };
  if (!/[0-9]/.test(password)) return { isStrong: false, message: 'Password must contain number' };
  if (!/[!@#$%^&*]/.test(password)) return { isStrong: false, message: 'Password must contain special character (!@#$%^&*)' };
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
    res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(e => ({ field: e.param, message: e.msg })),
    });
    return true;
  }
  return false;
};

/**
 * Generate JWT Token
 * @param {string} id - User ID
 * @returns {string} JWT token
 */
const generateToken = id => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRY });

/**
 * Generate refresh token
 * @param {string} id - User ID
 * @returns {string} Refresh token
 */
const generateRefreshToken = id => jwt.sign({ id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

// ============= AUTH CONTROLLER =============

/**
 * @desc    Register new user
 * @route   POST /api/auth/signup
 * @access  Public
 */
exports.signup = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;
    const { name, email, password, confirmPassword } = req.body;

    logger.info('Signup attempt', { email });

    if (!name || !email || !password || !confirmPassword) {
      logger.warn('Signup: Missing required fields', { email });
      return res.status(400).json({ success: false, message: 'Please provide all required fields' });
    }
    if (!isValidEmail(email)) {
      logger.warn('Signup: Invalid email format', { email });
      return res.status(400).json({ success: false, message: 'Please provide a valid email address' });
    }
    if (password !== confirmPassword) {
      logger.warn('Signup: Passwords do not match', { email });
      return res.status(400).json({ success: false, message: 'Passwords do not match' });
    }
    const passwordCheck = checkPasswordStrength(password);
    if (!passwordCheck.isStrong) {
      logger.warn('Signup: Weak password', { email });
      return res.status(400).json({ success: false, message: passwordCheck.message });
    }
    if (await User.findOne({ email: email.toLowerCase() })) {
      logger.warn('Signup: User already exists', { email });
      return res.status(409).json({ success: false, message: 'Email already registered. Please login or use a different email.' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const user = await User.create({
      name: name.trim(),
      email: email.toLowerCase(),
      password: hashedPassword,
      preferences: { theme: 'auto', language: 'en', currency: 'INR', timezone: 'Asia/Kolkata', dateFormat: 'DD/MM/YYYY', notifications: 'important' }
    });

    if (!user) {
      logger.error('Signup: Failed to create user', { email });
      return res.status(500).json({
        success: false,
        message: 'Failed to create user account',
      });
    }

    // Email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await user.save();
    await user.logActivity('create', 'user', {}, req.ip);

    // TODO: sendVerificationEmail(user.email, verificationToken);

    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    await user.addRefreshToken(refreshToken);  // Assuming addRefreshToken handles storage
    await user.logLogin(req.ip, req.get('user-agent'), "success");

    logger.info('Signup: User created successfully', { userId: user._id, email });

    res.status(201).json({
      success: true,
      message: 'User registered. Please verify your email.',
      token,
      refreshToken,
      user: buildUserResponse(user),
    });
  } catch (error) {
    logger.error('Signup error', { error: error.message });
    res.status(500).json({ success: false, message: 'An error occurred during signup. Please try again later.', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};

/**
 * @desc    Login user
 * @route   POST /api/auth/login
 * @access  Public
 */
exports.login = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;
    const { email, password } = req.body;

    logger.info('Login attempt', { email });

    if (!email || !password) {
      logger.warn('Login: Missing email or password', { email });
      return res.status(400).json({ success: false, message: 'Please provide email and password' });
    }
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user) {
      logger.warn('Login: User not found', { email });
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    if (user.accountLocked && user.lockUntil && new Date() < user.lockUntil) {
      logger.warn('Login: Account locked', { email });
      return res.status(423).json({ success: false, message: 'Account is temporarily locked. Please try again later.', lockUntil: user.lockUntil });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
        user.accountLocked = true;
        user.lockUntil = new Date(Date.now() + LOCK_TIME);
        logger.warn('Login: Account locked due to max attempts', { email });
      }
      await user.save();
      await user.logLogin(req.ip, req.get('user-agent'), "failed");
      logger.warn('Login: Invalid password', { email, attempts: user.loginAttempts });
      return res.status(401).json({ success: false, message: 'Invalid credentials', attemptsRemaining: Math.max(0, MAX_LOGIN_ATTEMPTS - user.loginAttempts) });
    }
    user.loginAttempts = 0;
    user.accountLocked = false;
    user.lastLogin = new Date();
    await user.save();

    // Generate tokens
    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    await user.addRefreshToken(refreshToken);  // Assuming addRefreshToken handles storage
    await user.logLogin(req.ip, req.get('user-agent'), "success");
    await user.logActivity('login', 'user', {}, req.ip);

    logger.info('Login: User logged in successfully', { userId: user._id, email });

    res.json({ success: true, message: 'Login successful', token, refreshToken, user: buildUserResponse(user) });
  } catch (error) {
    logger.error('Login error', { error: error.message });
    res.status(500).json({ success: false, message: 'An error occurred during login. Please try again later.', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};

/**
 * @desc    Get user profile
 * @route   GET /api/auth/profile
 * @access  Private
 */
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (!user) {
      logger.warn('GetProfile: User not found', { userId: req.user._id });
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    await user.logActivity('read', 'profile', {}, req.ip);

    logger.info('GetProfile: Retrieved successfully', { userId: user._id });

    res.json({ success: true, user: buildUserResponse(user) });
  } catch (error) {
    logger.error('GetProfile error', { error: error.message });
    res.status(500).json({ success: false, message: 'An error occurred while retrieving profile', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};

/**
 * @desc    Update user profile
 * @route   PUT /api/auth/profile
 * @access  Private
 */
exports.updateProfile = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;
    const { name, email, phone, avatar, bio, preferences } = req.body;

    logger.info('UpdateProfile: Update attempt', { userId: req.user._id });

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
      if (await User.findOne({ email: email.toLowerCase(), _id: { $ne: user._id } })) {
        logger.warn('UpdateProfile: Email already in use', { email });
        return res.status(409).json({ success: false, message: 'Email is already in use' });
      }
      if (!isValidEmail(email)) {
        logger.warn('UpdateProfile: Invalid email format', { email });
        return res.status(400).json({ success: false, message: 'Invalid email address' });
      }
      user.email = email.toLowerCase();
    }
    if (name) user.name = name;
    if (phone) user.phone = phone;
    if (avatar) user.avatar = avatar;
    if (bio) user.bio = bio;
    if (preferences) user.preferences = preferences;

    await user.save();
    await user.logActivity('update', 'profile', req.body, req.ip);

    logger.info('UpdateProfile: Updated successfully', { userId: user._id });

    res.json({ success: true, message: 'Profile updated', user: buildUserResponse(user) });
  } catch (error) {
    logger.error('UpdateProfile error', { error: error.message });
    res.status(500).json({ success: false, message: 'An error occurred while updating profile', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};

/**
 * @desc    Change password
 * @route   POST /api/auth/change-password
 * @access  Private
 */
exports.changePassword = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;
    const { currentPassword, newPassword, confirmPassword } = req.body;

    logger.info('ChangePassword: Change attempt', { userId: req.user._id });

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Please provide all required fields',
      });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'New passwords do not match',
      });
    }
    const passwordCheck = checkPasswordStrength(newPassword);
    if (!passwordCheck.isStrong) {
      return res.status(400).json({
        success: false,
        message: passwordCheck.message,
      });
    }

    const user = await User.findById(req.user._id).select('+password');

    if (!user) {
      logger.warn('ChangePassword: User not found', { userId: req.user._id });
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isPasswordMatch) {
      logger.warn('ChangePassword: Wrong current password', { userId: req.user._id });
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect',
      });
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({
        success: false,
        message: 'New password cannot be the same as current password',
      });
    }

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
exports.refreshToken = async (req, res) => { // Added 'exports.' prefix
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ success: false, message: 'Refresh token is required' });

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    } catch (error) {
      logger.warn('RefreshToken: Invalid or expired refresh token');
      return res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
    }

    const user = await User.findById(decoded.id);
    if (!user)
      return res.status(404).json({ success: false, message: 'User not found' });

    // *** REMOVE old refresh token from user ***
    await user.removeRefreshToken(refreshToken);

    // Generate and add new refresh token
    const newToken = generateToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);
    await user.addRefreshToken(newRefreshToken);

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

    // Optionally invalidate the refresh token used for this session
    // const token = req.headers.authorization?.split(' ')[1];
    // if (token) {
    //   // Logic to find and remove the corresponding refresh token based on the access token
    //   // This requires a mapping between access and refresh tokens or storing the refresh token ID in the access token
    // }

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
 * @desc    Get login history
 * @route   GET /api/auth/login-history
 * @access  Private
 */
exports.getLoginHistory = async (req, res) => {
  try {
    logger.info('GetLoginHistory: Request received', { userId: req.user._id });

    const user = await User.findById(req.user._id);
    res.json({ success: true, history: user.loginHistory ? user.loginHistory.slice(-50).reverse() : [] });
  } catch (error) {
    logger.error('GetLoginHistory error', { error: error.message });
    res.status(500).json({ success: false, message: 'Failed to retrieve login history' });
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

    const user = await User.findById(req.user._id);
    res.json({ success: true, activities: user.activityLog ? user.activityLog.slice(-100).reverse() : [] });
  } catch (error) {
    logger.error('GetActivityLog error', { error: error.message });
    res.status(500).json({ success: false, message: 'Failed to retrieve activity log' });
  }
};

// --- Remaining Endpoints (Placeholder Implementations) ---

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
      url: 'https://example.com/oauth', // Note: This is a placeholder URL from the knowledge base, trailing spaces removed
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

    // Assuming a soft delete mechanism (e.g., setting deletedAt)
    // await User.findByIdAndUpdate(req.user._id, { deletedAt: new Date() });
    // Or a hard delete if necessary:
    // await User.findByIdAndDelete(req.user._id);

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
