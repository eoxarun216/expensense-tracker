// controllers/authController.js - Simplified Version with getProfile
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const logger = require('../utils/logger');
const { validationResult } = require('express-validator');
// Removed unused crypto

const JWT_EXPIRY = '24h';
const SALT_ROUNDS = 10; // Removed MAX_LOGIN_ATTEMPTS, LOCK_TIME, REFRESH_TOKEN_EXPIRY

// ============= HELPER FUNCTIONS =============

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
    // isEmailVerified: user.isEmailVerified, // Removed
    preferences: user.preferences,
    subscription: user.subscription,
    lastLogin: user.lastLogin,
    // lastActivityAt: user.lastActivityAt, // Removed
    memberSince: user.createdAt,
    // loginHistory: user.loginHistory ? user.loginHistory.slice(-50).reverse() : [], // Removed
    // activityLog: user.activityLog ? user.activityLog.slice(-100).reverse() : [], // Removed
    isPremium: (user.role === 'premium' || (user.subscription && user.subscription.type !== 'free')),
    // deletedAt: user.deletedAt, // Removed
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
}

const isValidEmail = email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const checkPasswordStrength = password => {
  // Removed strength check for simplicity, assuming any non-empty password is acceptable
  // You might want to keep a basic check like minimum length
  if (password.length < 6) return { isStrong: false, message: 'Password must be at least 6 characters' };
  return { isStrong: true, message: 'Password is acceptable' };
};

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

const generateToken = id => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRY });
// Removed generateRefreshToken

// ============= AUTH CONTROLLER =============

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

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      logger.warn('Signup: User already exists', { email });
      return res.status(409).json({ success: false, message: 'Email already registered. Please login or use a different email.' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    logger.debug('Signup: Password hashed successfully', { email });

    const userData = {
      name: name.trim(),
      email: email.toLowerCase(),
      password: hashedPassword,
      preferences: { theme: 'auto', language: 'en', currency: 'INR', timezone: 'Asia/Kolkata', dateFormat: 'DD/MM/YYYY', notifications: 'important' }
    };

    const user = await User.create(userData);

    if (!user) {
      logger.error('Signup: Failed to create user (User.create returned null/undefined)', { email });
      return res.status(500).json({ success: false, message: 'Failed to create user account' });
    }

    logger.info('Signup: User registered successfully', { userId: user._id, email });

    // Generate token for immediate login
    const token = generateToken(user._id);
    // Removed refreshToken logic

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      // refreshToken, // Removed
      user: buildUserResponse(user),
    });
  } catch (error) {
    logger.error('Signup error', { error: error.message, stack: error.stack });
    // Removed specific password validation error handling
    res.status(500).json({ success: false, message: 'An error occurred during signup. Please try again later.', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};

exports.login = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;
    const { email, password } = req.body;

    logger.info('Login attempt', { email });

    if (!email || !password) {
      logger.warn('Login: Missing email or password', { email });
      return res.status(400).json({ success: false, message: 'Please provide email and password' });
    }

    const user = await User.findOne({ email: email.toLowerCase() }).select('+password'); // Use select('+password') to ensure it's fetched

    if (!user) {
      logger.warn('Login: User not found', { email });
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Removed account lockout logic
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      logger.warn('Login: Invalid password', { email });
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Removed updating login attempts and lock status
    user.lastLogin = new Date();
    await user.save(); // Save the updated lastLogin time

    const token = generateToken(user._id);
    // Removed refreshToken logic

    logger.info('Login: User logged in successfully', { userId: user._id, email });

    res.json({ success: true, message: 'Login successful', token, user: buildUserResponse(user) });
  } catch (error) {
    logger.error('Login error', { error: error.message });
    res.status(500).json({ success: false, message: 'An error occurred during login. Please try again later.', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};

// --- ADDED getProfile function ---
exports.getProfile = async (req, res) => {
  try {
    // req.user should be attached by the 'protect' middleware
    const user = req.user;

    if (!user) {
      // This shouldn't happen if protect middleware works correctly,
      // but good to check for robustness.
      logger.warn('GetProfile: User not attached to request by middleware', { userId: req.user?._id });
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    logger.info('GetProfile: Retrieved successfully', { userId: user._id });

    // Use the buildUserResponse helper
    res.json({ success: true, user: buildUserResponse(user) });
  } catch (error) {
    logger.error('GetProfile error', { error: error.message });
    res.status(500).json({ success: false, message: 'An error occurred while retrieving profile', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};
// --- END ADDED ---

// Removed refreshToken, updateProfile, changePassword,
// requestPasswordReset, resetPassword, verifyEmail, requestEmailVerification,
// getLoginHistory, getActivityLog, deleteAccount, logout functions
