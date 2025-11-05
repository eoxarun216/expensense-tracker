const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const logger = require('../utils/logger');
const { validationResult } = require('express-validator');
const crypto = require('crypto');

const JWT_EXPIRY = '24h';
const REFRESH_TOKEN_EXPIRY = '7d';
const SALT_ROUNDS = 10;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes in milliseconds

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
    isEmailVerified: user.isEmailVerified,
    preferences: user.preferences,
    subscription: user.subscription,
    lastLogin: user.lastLogin,
    lastActivityAt: user.lastActivityAt,
    memberSince: user.createdAt,
    loginHistory: user.loginHistory ? user.loginHistory.slice(-50).reverse() : [],
    activityLog: user.activityLog ? user.activityLog.slice(-100).reverse() : [],
    isPremium: (user.role === 'premium' || (user.subscription && user.subscription.type !== 'free')),
    deletedAt: user.deletedAt,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
}

const isValidEmail = email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const checkPasswordStrength = password => {
  if (password.length < 8) return { isStrong: false, message: 'Password must be at least 8 characters' };
  if (!/[A-Z]/.test(password)) return { isStrong: false, message: 'Password must contain uppercase letter' };
  if (!/[a-z]/.test(password)) return { isStrong: false, message: 'Password must contain lowercase letter' };
  if (!/[0-9]/.test(password)) return { isStrong: false, message: 'Password must contain number' };
  if (!/[!@#$%^&*]/.test(password)) return { isStrong: false, message: 'Password must contain special character (!@#$%^&*)' };
  return { isStrong: true, message: 'Password is strong' };
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
const generateRefreshToken = id => jwt.sign({ id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

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

    if (!password || typeof password !== 'string' || password.trim().length === 0) {
        logger.error('Signup: Password is invalid (empty, not a string, or undefined)', { email, passwordReceived: typeof password });
        return res.status(400).json({ success: false, message: 'Password is required and must be a valid string' });
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

    logger.debug('Signup: User document created in DB', { userId: user._id, email: user.email });

    const verificationToken = crypto.randomBytes(32).toString('hex');
    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await user.save();
    await user.logActivity('create', 'user', {}, req.ip);

    // TODO: sendVerificationEmail(user.email, verificationToken);

    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    await user.addRefreshToken(refreshToken);
    await user.logLogin(req.ip, req.get('user-agent'), 'success');

    logger.info('Signup: User registered successfully', { userId: user._id, email });

    res.status(201).json({
      success: true,
      message: 'User registered. Please verify your email.',
      token,
      refreshToken,
      user: buildUserResponse(user),
    });
  } catch (error) {
    logger.error('Signup error', { error: error.message, stack: error.stack });
    if (error.name === 'ValidationError' && error.errors && error.errors.password) {
      logger.error('Signup error: Mongoose validation failed for password field', { error: error.message });
      return res.status(400).json({ success: false, message: 'Password validation failed during account creation. Please ensure your password meets the requirements.' });
    }
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

    const user = await User.findOne({ email: email.toLowerCase() }).select('+password').lean();

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
      const updatedUser = await User.findOneAndUpdate(
        { email: email.toLowerCase() },
        {
          $inc: { loginAttempts: 1 },
          $set: {
            ...( (user.loginAttempts || 0) + 1 >= MAX_LOGIN_ATTEMPTS ? { accountLocked: true, lockUntil: new Date(Date.now() + LOCK_TIME) } : {} )
          }
        },
        { new: true, runValidators: false }
      ).select('loginAttempts');

      if (updatedUser) {
         logger.warn('Login: Invalid password', { email, attempts: updatedUser.loginAttempts });
      } else {
         logger.error('Login: Failed to update login attempts for invalid password', { email });
      }

      const remainingAttempts = Math.max(0, MAX_LOGIN_ATTEMPTS - ((user.loginAttempts || 0) + 1));
      return res.status(401).json({ success: false, message: 'Invalid credentials', attemptsRemaining: remainingAttempts });
    }

    const updatedUserOnSuccess = await User.findOneAndUpdate(
      { email: email.toLowerCase() },
      { $set: { loginAttempts: 0, accountLocked: false, lastLogin: new Date() } },
      { new: true, runValidators: false }
    ).select('name email role');

    const token = generateToken(user._id.toString());
    const refreshToken = generateRefreshToken(user._id.toString());

    logger.info('Login: User logged in successfully', { userId: user._id, email });

    res.json({ success: true, message: 'Login successful', token, refreshToken, user: buildUserResponse(user) });
  } catch (error) {
    logger.error('Login error', { error: error.message });
    if (error.name === 'ValidationError' && error.errors && error.errors.password) {
      logger.error('Login error: Password validation failed unexpectedly', { error: error.message });
      return res.status(500).json({ success: false, message: 'Internal server configuration error. Please contact support.' });
    }
    res.status(500).json({ success: false, message: 'An error occurred during login. Please try again later.', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};

exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ success: false, message: 'Refresh token is required' });

    let decoded;
    try { decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET); } catch (error) {
      logger.warn('RefreshToken: Invalid or expired refresh token');
      return res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
    }

    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    await user.removeRefreshToken(refreshToken);

    const newToken = generateToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);
    await user.addRefreshToken(newRefreshToken);

    logger.info('RefreshToken: Tokens refreshed successfully', { userId: user._id });

    res.json({ success: true, message: 'Tokens refreshed successfully', token: newToken, refreshToken: newRefreshToken });
  } catch (error) {
    logger.error('RefreshToken error', { error: error.message });
    res.status(500).json({ success: false, message: 'An error occurred while refreshing token', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};

exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      logger.warn('GetProfile: User not found', { userId: req.user._id });
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    await user.logActivity('read', 'profile', {}, req.ip);
    logger.info('GetProfile: Retrieved successfully', { userId: user._id });
    res.json({ success: true, user: buildUserResponse(user) });
  } catch (error) {
    logger.error('GetProfile error', { error: error.message });
    res.status(500).json({ success: false, message: 'An error occurred while retrieving profile', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;
    const { name, email, phone, avatar, bio, preferences } = req.body;

    logger.info('UpdateProfile: Update attempt', { userId: req.user._id });

    let user = await User.findById(req.user._id);
    if (!user) {
      logger.warn('UpdateProfile: User not found', { userId: req.user._id });
      return res.status(404).json({ success: false, message: 'User not found' });
    }

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

exports.changePassword = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;
    const { currentPassword, newPassword, confirmPassword } = req.body;

    logger.info('ChangePassword: Change attempt', { userId: req.user._id });

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ success: false, message: 'Please provide all required fields' });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'New passwords do not match' });
    }
    const passwordCheck = checkPasswordStrength(newPassword);
    if (!passwordCheck.isStrong) {
      return res.status(400).json({ success: false, message: passwordCheck.message });
    }

    const user = await User.findById(req.user._id).select('+password');
    if (!user) {
      logger.warn('ChangePassword: User not found', { userId: req.user._id });
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordMatch) {
      logger.warn('ChangePassword: Wrong current password', { userId: req.user._id });
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ success: false, message: 'New password cannot be the same as current password' });
    }

    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    user.password = await bcrypt.hash(newPassword, salt);
    user.passwordChangedAt = new Date();

    await user.save();

    logger.info('ChangePassword: Password changed successfully', { userId: user._id });

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    logger.error('ChangePassword error', { error: error.message });
    res.status(500).json({ success: false, message: 'An error occurred while changing password', error: process.env.NODE_ENV === 'development' ? error.message : undefined });
  }
};

exports.requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    logger.info('RequestPasswordReset: Request received', { email });

    if (user) {
      // Generate reset token and expiry
      const resetToken = crypto.randomBytes(32).toString('hex');
      user.passwordResetToken = resetToken;
      user.passwordResetExpires = Date.now() + 60 * 60 * 1000; // 1 hour
      await user.save();
      // TODO: sendPasswordResetEmail(user.email, resetToken);
    }

    // Always respond positively to avoid user enumeration
    res.json({ success: true, message: 'If email exists, password reset link has been sent' });
  } catch (error) {
    logger.error('RequestPasswordReset error', { error: error.message });
    res.status(500).json({ success: false, message: 'Password reset request failed' });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;
    if (password !== confirmPassword) return res.status(400).json({ success: false, message: 'Passwords do not match' });
    const passwordCheck = checkPasswordStrength(password);
    if (!passwordCheck.isStrong) return res.status(400).json({ success: false, message: passwordCheck.message });

    const user = await User.findOne({ passwordResetToken: token, passwordResetExpires: { $gt: Date.now() } }).select('+password');
    if (!user) return res.status(400).json({ success: false, message: 'Invalid or expired token' });

    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    user.password = await bcrypt.hash(password, salt);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangedAt = new Date();

    await user.save();

    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    logger.error('ResetPassword error', { error: error.message });
    res.status(500).json({ success: false, message: 'Password reset failed' });
  }
};

exports.verifyEmail = async (req, res) => {
  try {
    const { token } = req.body;
    const user = await User.findOne({ emailVerificationToken: token, emailVerificationExpires: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ success: false, message: 'Invalid or expired token' });

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    logger.info('VerifyEmail: Email verified', { userId: user._id });

    res.json({ success: true, message: 'Email verified successfully' });
  } catch (error) {
    logger.error('VerifyEmail error', { error: error.message });
    res.status(500).json({ success: false, message: 'Email verification failed' });
  }
};

exports.requestEmailVerification = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const verificationToken = crypto.randomBytes(32).toString('hex');
    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await user.save();

    // TODO: sendVerificationEmail(user.email, verificationToken);

    res.json({ success: true, message: 'Verification email sent' });
  } catch (error) {
    logger.error('RequestEmailVerification error', { error: error.message });
    res.status(500).json({ success: false, message: 'Request failed' });
  }
};

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

exports.deleteAccount = async (req, res) => {
  try {
    const { password } = req.body;
    const user = await User.findById(req.user._id).select('+password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      logger.warn('DeleteAccount: Invalid password', { userId: req.user._id });
      return res.status(401).json({ success: false, message: 'Password is incorrect' });
    }

    // Soft delete by default
    await User.findByIdAndUpdate(req.user._id, { deletedAt: new Date() });

    logger.info('DeleteAccount: Account deleted', { userId: req.user._id });

    res.json({ success: true, message: 'Account deleted successfully' });
  } catch (error) {
    logger.error('DeleteAccount error', { error: error.message });
    res.status(500).json({ success: false, message: 'Account deletion failed' });
  }
};

exports.logout = async (req, res) => {
  try {
    logger.info('Logout: User logging out', { userId: req.user._id });

    // Optionally invalidate the refresh token used for this session if provided
    const { refreshToken } = req.body;
    if (refreshToken && req.user && req.user._id) {
      const user = await User.findById(req.user._id);
      if (user) await user.removeRefreshToken(refreshToken);
    }

    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    logger.error('Logout error', { error: error.message });
    res.status(500).json({ success: false, message: 'An error occurred during logout' });
  }
};
