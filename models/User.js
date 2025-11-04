// File: models/User.js

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// ============= ENUMS =============

const USER_ROLES = {
  USER: 'user',
  PREMIUM: 'premium',
  ADMIN: 'admin',
};

const ACCOUNT_STATUS = {
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  SUSPENDED: 'suspended',
  DELETED: 'deleted',
};

const NOTIFICATION_PREFERENCES = {
  ALL: 'all',
  IMPORTANT: 'important',
  NONE: 'none',
};

// ============= USER SCHEMA =============

const UserSchema = new mongoose.Schema(
  {
    // ============= BASIC INFORMATION =============

    name: {
      type: String,
      required: [true, 'Please add a name'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters'],
      maxlength: [100, 'Name cannot exceed 100 characters'],
    },

    email: {
      type: String,
      required: [true, 'Please add an email'],
      unique: [true, 'Email already exists'],
      lowercase: true,
      trim: true,
      match: [
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        'Please add a valid email',
      ],
      index: true,
    },

    password: {
      type: String,
      required: [true, 'Please add a password'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false, // Don't return password by default
    },

    phone: {
      type: String,
      trim: true,
      match: [/^[+]?[(]?[0-9]{1,4}[)]?[-\s.]?[(]?[0-9]{1,4}[)]?[-\s.]?[0-9]{1,9}$/, 'Please add a valid phone number'],
    },

    avatar: {
      type: String,
      default: null,
    },

    bio: {
      type: String,
      maxlength: [500, 'Bio cannot exceed 500 characters'],
    },

    // ============= ACCOUNT MANAGEMENT =============

    role: {
      type: String,
      enum: {
        values: Object.values(USER_ROLES),
        message: 'Invalid role',
      },
      default: USER_ROLES.USER,
    },

    status: {
      type: String,
      enum: {
        values: Object.values(ACCOUNT_STATUS),
        message: 'Invalid account status',
      },
      default: ACCOUNT_STATUS.ACTIVE,
      index: true,
    },

    isEmailVerified: {
      type: Boolean,
      default: false,
    },

    emailVerificationToken: String,
    emailVerificationExpires: Date,

    isPhoneVerified: {
      type: Boolean,
      default: false,
    },

    phoneVerificationToken: String,
    phoneVerificationExpires: Date,

    // ============= PASSWORD MANAGEMENT =============

    passwordChangedAt: Date,

    passwordResetToken: String,
    passwordResetExpires: Date,

    // ============= SECURITY =============

    loginAttempts: {
      type: Number,
      default: 0,
    },

    accountLocked: {
      type: Boolean,
      default: false,
    },

    lockUntil: Date,

    loginHistory: [
      {
        date: {
          type: Date,
          default: Date.now,
        },
        ipAddress: String,
        userAgent: String,
        status: {
          type: String,
          enum: ['success', 'failed'],
          default: 'success',
        },
      },
    ],

    lastLogin: Date,
    lastLoginAt: Date,

    refreshTokens: [
      {
        token: String,
        createdAt: {
          type: Date,
          default: Date.now,
          expires: 604800, // 7 days
        },
      },
    ],

    // ============= PREFERENCES =============

    preferences: {
      theme: {
        type: String,
        enum: ['light', 'dark', 'auto'],
        default: 'auto',
      },
      language: {
        type: String,
        enum: ['en', 'es', 'fr', 'de', 'it', 'hi', 'other'],
        default: 'en',
      },
      currency: {
        type: String,
        default: 'INR',
      },
      timezone: {
        type: String,
        default: 'Asia/Kolkata',
      },
      dateFormat: {
        type: String,
        enum: ['DD/MM/YYYY', 'MM/DD/YYYY', 'YYYY-MM-DD'],
        default: 'DD/MM/YYYY',
      },
      notifications: {
        type: String,
        enum: Object.values(NOTIFICATION_PREFERENCES),
        default: NOTIFICATION_PREFERENCES.IMPORTANT,
      },
      emailNotifications: {
        type: Boolean,
        default: true,
      },
      pushNotifications: {
        type: Boolean,
        default: true,
      },
      smsNotifications: {
        type: Boolean,
        default: false,
      },
    },

    // ============= SUBSCRIPTION & BILLING =============

    subscription: {
      type: {
        type: String,
        enum: ['free', 'monthly', 'yearly', 'lifetime'],
        default: 'free',
      },
      status: {
        type: String,
        enum: ['active', 'inactive', 'cancelled', 'expired'],
        default: 'active',
      },
      startDate: Date,
      endDate: Date,
      autoRenew: {
        type: Boolean,
        default: true,
      },
      planName: String,
      price: {
        type: Number,
        default: 0,
      },
    },

    billingInfo: {
      fullName: String,
      address: String,
      city: String,
      state: String,
      postalCode: String,
      country: String,
      cardLast4: String,
    },

    // ============= ACTIVITY TRACKING =============

    totalExpenses: {
      type: Number,
      default: 0,
    },

    totalReminders: {
      type: Number,
      default: 0,
    },

    totalBudgets: {
      type: Number,
      default: 0,
    },

    totalSpent: {
      type: Number,
      default: 0,
    },

    lastActivityAt: Date,

    activityLog: [
      {
        action: {
          type: String,
          enum: ['login', 'logout', 'create', 'update', 'delete', 'export'],
        },
        resource: String,
        timestamp: {
          type: Date,
          default: Date.now,
        },
        ipAddress: String,
        details: mongoose.Schema.Types.Mixed,
      },
    ],

    // ============= TWO-FACTOR AUTHENTICATION =============

    twoFactorEnabled: {
      type: Boolean,
      default: false,
    },

    twoFactorSecret: String,

    twoFactorBackupCodes: [String],

    // ============= SOCIAL ACCOUNTS =============

    googleId: String,
    facebookId: String,
    githubId: String,

    // ============= DATA & PREFERENCES =============

    dataBackup: {
      lastBackupAt: Date,
      autoBackup: {
        type: Boolean,
        default: true,
      },
      backupFrequency: {
        type: String,
        enum: ['weekly', 'monthly', 'never'],
        default: 'weekly',
      },
    },

    dataExport: {
      lastExportAt: Date,
      format: {
        type: String,
        enum: ['json', 'csv', 'pdf'],
        default: 'json',
      },
    },

    // ============= AUDIT FIELDS =============

    tags: {
      type: [String],
      default: [],
    },

    metadata: mongoose.Schema.Types.Mixed,

    deletedAt: {
      type: Date,
      default: null,
    },

    createdAt: {
      type: Date,
      default: Date.now,
      index: true,
    },

    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ============= INDEXES =============

UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ status: 1 });
UserSchema.index({ role: 1 });
UserSchema.index({ createdAt: -1 });
UserSchema.index({ lastLogin: -1 });
UserSchema.index({ 'subscription.status': 1 });
UserSchema.index({ 'subscription.endDate': 1 });
UserSchema.index({ googleId: 1 });
UserSchema.index({ facebookId: 1 });
UserSchema.index({ githubId: 1 });

// ============= VIRTUAL FIELDS =============

/**
 * Get user's full profile summary
 */
UserSchema.virtual('profileSummary').get(function() {
  return {
    id: this._id,
    name: this.name,
    email: this.email,
    avatar: this.avatar,
    role: this.role,
    status: this.status,
    isEmailVerified: this.isEmailVerified,
    subscription: this.subscription.type,
    createdAt: this.createdAt,
  };
});

/**
 * Check if account is locked
 */
UserSchema.virtual('isAccountLocked').get(function() {
  return this.accountLocked && this.lockUntil && new Date() < this.lockUntil;
});

/**
 * Check if subscription is active
 */
UserSchema.virtual('isSubscriptionActive').get(function() {
  if (this.subscription.type === 'free') return true;
  return (
    this.subscription.status === 'active' &&
    (!this.subscription.endDate || new Date() < this.subscription.endDate)
  );
});

/**
 * Check if subscription is expiring soon (within 7 days)
 */
UserSchema.virtual('isSubscriptionExpiringSoon').get(function() {
  if (!this.subscription.endDate) return false;
  const sevenDaysFromNow = new Date();
  sevenDaysFromNow.setDate(sevenDaysFromNow.getDate() + 7);
  return this.subscription.endDate <= sevenDaysFromNow;
});

/**
 * Get days until subscription expires
 */
UserSchema.virtual('daysUntilSubscriptionExpires').get(function() {
  if (!this.subscription.endDate) return null;
  const now = new Date();
  const timeDiff = this.subscription.endDate - now;
  return Math.ceil(timeDiff / (1000 * 60 * 60 * 24));
});

/**
 * Check if premium user
 */
UserSchema.virtual('isPremium').get(function() {
  return this.role === USER_ROLES.PREMIUM || this.subscription.type !== 'free';
});

/**
 * Get member since
 */
UserSchema.virtual('memberSince').get(function() {
  return this.createdAt.toLocaleDateString('en-IN', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
});

/**
 * Check if recently active (last 7 days)
 */
UserSchema.virtual('isRecentlyActive').get(function() {
  if (!this.lastLogin) return false;
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  return this.lastLogin > sevenDaysAgo;
});

// ============= INSTANCE METHODS =============

/**
 * Encrypt password before saving
 */
UserSchema.methods.encryptPassword = async function(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};

/**
 * Compare password
 */
UserSchema.methods.comparePassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

/**
 * Get user profile (without sensitive data)
 */
UserSchema.methods.getProfile = function() {
  const profile = this.toObject();
  delete profile.password;
  delete profile.passwordResetToken;
  delete profile.passwordResetExpires;
  delete profile.emailVerificationToken;
  delete profile.phoneVerificationToken;
  delete profile.twoFactorSecret;
  delete profile.twoFactorBackupCodes;
  delete profile.refreshTokens;
  return profile;
};

/**
 * Log user login
 */
UserSchema.methods.logLogin = function(ipAddress, userAgent, status = 'success') {
  this.loginHistory.push({
    date: new Date(),
    ipAddress,
    userAgent,
    status,
  });

  // Keep only last 50 login attempts
  if (this.loginHistory.length > 50) {
    this.loginHistory = this.loginHistory.slice(-50);
  }

  if (status === 'success') {
    this.lastLogin = new Date();
    this.lastLoginAt = new Date();
    this.loginAttempts = 0;
    this.accountLocked = false;
  } else {
    this.loginAttempts = (this.loginAttempts || 0) + 1;

    // Lock account after 5 failed attempts
    if (this.loginAttempts >= 5) {
      this.accountLocked = true;
      this.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    }
  }

  return this.save();
};

/**
 * Log activity
 */
UserSchema.methods.logActivity = function(action, resource, details = {}, ipAddress = null) {
  this.activityLog.push({
    action,
    resource,
    timestamp: new Date(),
    ipAddress,
    details,
  });

  // Keep only last 100 activities
  if (this.activityLog.length > 100) {
    this.activityLog = this.activityLog.slice(-100);
  }

  this.lastActivityAt = new Date();
  return this.save();
};

/**
 * Add refresh token
 */
UserSchema.methods.addRefreshToken = function(token) {
  this.refreshTokens.push({
    token,
    createdAt: new Date(),
  });

  // Keep only last 10 refresh tokens
  if (this.refreshTokens.length > 10) {
    this.refreshTokens = this.refreshTokens.slice(-10);
  }

  return this.save();
};

/**
 * Remove refresh token
 */
UserSchema.methods.removeRefreshToken = function(token) {
  this.refreshTokens = this.refreshTokens.filter(rt => rt.token !== token);
  return this.save();
};

/**
 * Update last activity
 */
UserSchema.methods.updateLastActivity = function() {
  this.lastActivityAt = new Date();
  return this.save();
};

/**
 * Update subscription
 */
UserSchema.methods.updateSubscription = function(subscriptionData, userId = null) {
  Object.assign(this.subscription, subscriptionData);
  return this.save();
};

/**
 * Update preferences
 */
UserSchema.methods.updatePreferences = function(preferencesData) {
  Object.assign(this.preferences, preferencesData);
  return this.save();
};

/**
 * Suspend account
 */
UserSchema.methods.suspendAccount = function(reason = null) {
  this.status = ACCOUNT_STATUS.SUSPENDED;
  if (reason) {
    this.metadata = { ...this.metadata, suspensionReason: reason };
  }
  return this.save();
};

/**
 * Activate account
 */
UserSchema.methods.activateAccount = function() {
  this.status = ACCOUNT_STATUS.ACTIVE;
  return this.save();
};

/**
 * Soft delete account
 */
UserSchema.methods.softDelete = function() {
  this.status = ACCOUNT_STATUS.DELETED;
  this.deletedAt = new Date();
  return this.save();
};

/**
 * Enable two-factor authentication
 */
UserSchema.methods.enableTwoFactor = function(secret, backupCodes = []) {
  this.twoFactorEnabled = true;
  this.twoFactorSecret = secret;
  this.twoFactorBackupCodes = backupCodes;
  return this.save();
};

/**
 * Disable two-factor authentication
 */
UserSchema.methods.disableTwoFactor = function() {
  this.twoFactorEnabled = false;
  this.twoFactorSecret = null;
  this.twoFactorBackupCodes = [];
  return this.save();
};

/**
 * Verify email
 */
UserSchema.methods.verifyEmail = function() {
  this.isEmailVerified = true;
  this.emailVerificationToken = undefined;
  this.emailVerificationExpires = undefined;
  return this.save();
};

/**
 * Verify phone
 */
UserSchema.methods.verifyPhone = function() {
  this.isPhoneVerified = true;
  this.phoneVerificationToken = undefined;
  this.phoneVerificationExpires = undefined;
  return this.save();
};

/**
 * Update stats
 */
UserSchema.methods.updateStats = function(expenseCount, reminderCount, budgetCount, totalSpent) {
  this.totalExpenses = expenseCount || this.totalExpenses;
  this.totalReminders = reminderCount || this.totalReminders;
  this.totalBudgets = budgetCount || this.totalBudgets;
  this.totalSpent = totalSpent || this.totalSpent;
  return this.save();
};

// ============= STATIC METHODS =============

/**
 * Get user by email
 */
UserSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase() });
};

/**
 * Get users by role
 */
UserSchema.statics.findByRole = function(role) {
  return this.find({ role, status: ACCOUNT_STATUS.ACTIVE });
};

/**
 * Get active users
 */
UserSchema.statics.getActiveUsers = function() {
  return this.find({ status: ACCOUNT_STATUS.ACTIVE });
};

/**
 * Get premium users
 */
UserSchema.statics.getPremiumUsers = function() {
  return this.find({
    $or: [
      { role: USER_ROLES.PREMIUM },
      { 'subscription.status': 'active' },
    ],
  });
};

/**
 * Get users with expiring subscriptions
 */
UserSchema.statics.getExpiringSubscriptions = async function(daysThreshold = 7) {
  const thresholdDate = new Date();
  thresholdDate.setDate(thresholdDate.getDate() + daysThreshold);

  return this.find({
    'subscription.endDate': {
      $lte: thresholdDate,
      $gte: new Date(),
    },
    'subscription.status': 'active',
  });
};

/**
 * Get suspended users
 */
UserSchema.statics.getSuspendedUsers = function() {
  return this.find({ status: ACCOUNT_STATUS.SUSPENDED });
};

/**
 * Get recently active users
 */
UserSchema.statics.getRecentlyActive = function(days = 7) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);

  return this.find({
    lastLogin: { $gte: dateThreshold },
    status: ACCOUNT_STATUS.ACTIVE,
  });
};

/**
 * Get user statistics
 */
UserSchema.statics.getUserStatistics = async function() {
  const total = await this.countDocuments();
  const active = await this.countDocuments({ status: ACCOUNT_STATUS.ACTIVE });
  const premium = await this.countDocuments({ role: USER_ROLES.PREMIUM });
  const suspended = await this.countDocuments({ status: ACCOUNT_STATUS.SUSPENDED });
  const emailVerified = await this.countDocuments({ isEmailVerified: true });

  const totalSpent = await this.aggregate([
    { $group: { _id: null, total: { $sum: '$totalSpent' } } },
  ]);

  return {
    total,
    active,
    premium,
    suspended,
    emailVerified,
    totalSpent: totalSpent[0]?.total || 0,
  };
};

/**
 * Search users
 */
UserSchema.statics.searchUsers = async function(searchTerm, { limit = 20, skip = 0 } = {}) {
  const regex = new RegExp(searchTerm, 'i');
  const query = {
    $or: [{ name: regex }, { email: regex }, { phone: regex }],
  };

  const total = await this.countDocuments(query);
  const results = await this.find(query)
    .select('-password -refreshTokens -twoFactorSecret')
    .skip(skip)
    .limit(limit)
    .lean();

  return { results, total };
};

// ============= MIDDLEWARE =============

/**
 * Pre-save: Hash password if modified
 */
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    if (this.isModified('password')) {
      this.passwordChangedAt = new Date();
    }
    next();
  } catch (error) {
    next(error);
  }
});

/**
 * Post-save: Remove sensitive fields from response
 */
UserSchema.post('save', function(doc, next) {
  doc.password = undefined;
  doc.refreshTokens = undefined;
  doc.twoFactorSecret = undefined;
  next();
});

// ============= JSON OUTPUT OPTIONS =============

UserSchema.set('toJSON', {
  virtuals: true,
  transform: function(doc, ret) {
    delete ret.__v;
    delete ret.password;
    delete ret.refreshTokens;
    delete ret.twoFactorSecret;
    delete ret.twoFactorBackupCodes;
    delete ret.passwordResetToken;
    delete ret.emailVerificationToken;
    delete ret.phoneVerificationToken;
    if (ret.deletedAt) {
      delete ret.deletedAt;
    }
    return ret;
  },
});

UserSchema.set('toObject', { virtuals: true });

// ============= EXPORT =============

module.exports = mongoose.model('User', UserSchema);

// ============= EXPORT ENUMS & CONSTANTS =============

module.exports.USER_ROLES = USER_ROLES;
module.exports.ACCOUNT_STATUS = ACCOUNT_STATUS;
module.exports.NOTIFICATION_PREFERENCES = NOTIFICATION_PREFERENCES;
