// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 10; // centralize salt rounds

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
      match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please add a valid email'],
      index: true,
    },

    password: {
      type: String,
      required: [true, 'Please add a password'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false,
    },

    phone: {
      type: String,
      trim: true,
      match: [
        /^[+]?[(]?[0-9]{1,4}[)]?[-\s.]?[(]?[0-9]{1,4}[)]?[-\s.]?[0-9]{1,9}$/,
        'Please add a valid phone number',
      ],
    },

    avatar: { type: String, default: null },
    bio: { type: String, maxlength: [500, 'Bio cannot exceed 500 characters'] },

    // ACCOUNT MANAGEMENT
    role: {
      type: String,
      enum: Object.values(USER_ROLES),
      default: USER_ROLES.USER,
    },

    status: {
      type: String,
      enum: Object.values(ACCOUNT_STATUS),
      default: ACCOUNT_STATUS.ACTIVE,
      index: true,
    },

    isEmailVerified: { type: Boolean, default: false },
    emailVerificationToken: String,
    emailVerificationExpires: Date,

    isPhoneVerified: { type: Boolean, default: false },
    phoneVerificationToken: String,
    phoneVerificationExpires: Date,

    // PASSWORD MANAGEMENT
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,

    // SECURITY
    loginAttempts: { type: Number, default: 0 },
    accountLocked: { type: Boolean, default: false },
    lockUntil: Date,

    loginHistory: [
      {
        date: { type: Date, default: Date.now },
        ipAddress: String,
        userAgent: String,
        status: { type: String, enum: ['success', 'failed'], default: 'success' },
      },
    ],

    lastLogin: Date,
    lastLoginAt: Date,

    // Refresh tokens stored as subdocuments (no TTL here — see note).
    // NOTE: TTL on subdocument fields does NOT auto-remove subdocs.
    // Use a separate collection or a periodic cleanup job if you need automatic expiry.
    refreshTokens: [
      {
        token: String,
        createdAt: { type: Date, default: Date.now },
      },
    ],

    // PREFERENCES
    preferences: {
      theme: { type: String, enum: ['light', 'dark', 'auto'], default: 'auto' },
      language: { type: String, enum: ['en', 'es', 'fr', 'de', 'it', 'hi', 'other'], default: 'en' },
      currency: { type: String, default: 'INR' },
      timezone: { type: String, default: 'Asia/Kolkata' },
      dateFormat: { type: String, enum: ['DD/MM/YYYY', 'MM/DD/YYYY', 'YYYY-MM-DD'], default: 'DD/MM/YYYY' },
      notifications: { type: String, enum: Object.values(NOTIFICATION_PREFERENCES), default: NOTIFICATION_PREFERENCES.IMPORTANT },
      emailNotifications: { type: Boolean, default: true },
      pushNotifications: { type: Boolean, default: true },
      smsNotifications: { type: Boolean, default: false },
    },

    subscription: {
      type: {
        type: String,
        enum: ['free', 'monthly', 'yearly', 'lifetime'],
        default: 'free',
      },
      status: { type: String, enum: ['active', 'inactive', 'cancelled', 'expired'], default: 'active' },
      startDate: Date,
      endDate: Date,
      autoRenew: { type: Boolean, default: true },
      planName: String,
      price: { type: Number, default: 0 },
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

    // ACTIVITY
    totalExpenses: { type: Number, default: 0 },
    totalReminders: { type: Number, default: 0 },
    totalBudgets: { type: Number, default: 0 },
    totalSpent: { type: Number, default: 0 },

    lastActivityAt: Date,

    activityLog: [
      {
        action: { type: String, enum: ['login', 'logout', 'create', 'update', 'delete', 'export'] },
        resource: String,
        timestamp: { type: Date, default: Date.now },
        ipAddress: String,
        details: mongoose.Schema.Types.Mixed,
      },
    ],

    // TWO-FACTOR (optional — keep if you plan to re-enable)
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: String,
    twoFactorBackupCodes: [String],

    // SOCIAL (optional)
    googleId: String,
    facebookId: String,
    githubId: String,

    // METADATA
    dataBackup: {
      lastBackupAt: Date,
      autoBackup: { type: Boolean, default: true },
      backupFrequency: { type: String, enum: ['weekly', 'monthly', 'never'], default: 'weekly' },
    },

    dataExport: {
      lastExportAt: Date,
      format: { type: String, enum: ['json', 'csv', 'pdf'], default: 'json' },
    },

    tags: { type: [String], default: [] },
    metadata: mongoose.Schema.Types.Mixed,

    deletedAt: { type: Date, default: null },

    createdAt: { type: Date, default: Date.now, index: true },
    updatedAt: { type: Date, default: Date.now },
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

// ============= VIRTUALS =============
UserSchema.virtual('profileSummary').get(function () {
  return {
    id: this._id,
    name: this.name,
    email: this.email,
    avatar: this.avatar,
    role: this.role,
    status: this.status,
    isEmailVerified: this.isEmailVerified,
    subscription: this.subscription && this.subscription.type,
    createdAt: this.createdAt,
  };
});

UserSchema.virtual('isAccountLocked').get(function () {
  return this.accountLocked && this.lockUntil && new Date() < this.lockUntil;
});

UserSchema.virtual('isSubscriptionActive').get(function () {
  if (!this.subscription) return false;
  if (this.subscription.type === 'free') return true;
  return this.subscription.status === 'active' && (!this.subscription.endDate || new Date() < this.subscription.endDate);
});

UserSchema.virtual('isSubscriptionExpiringSoon').get(function () {
  if (!this.subscription || !this.subscription.endDate) return false;
  const sevenDaysFromNow = new Date();
  sevenDaysFromNow.setDate(sevenDaysFromNow.getDate() + 7);
  return this.subscription.endDate <= sevenDaysFromNow;
});

UserSchema.virtual('daysUntilSubscriptionExpires').get(function () {
  if (!this.subscription || !this.subscription.endDate) return null;
  const now = new Date();
  const timeDiff = this.subscription.endDate - now;
  return Math.ceil(timeDiff / (1000 * 60 * 60 * 24));
});

UserSchema.virtual('isPremium').get(function () {
  if (!this.subscription) return this.role === USER_ROLES.PREMIUM;
  return this.role === USER_ROLES.PREMIUM || this.subscription.type !== 'free';
});

UserSchema.virtual('memberSince').get(function () {
  if (!this.createdAt) return null;
  return this.createdAt.toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' });
});

UserSchema.virtual('isRecentlyActive').get(function () {
  if (!this.lastLogin) return false;
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  return this.lastLogin > sevenDaysAgo;
});

// ============= INSTANCE METHODS =============

UserSchema.methods.encryptPassword = async function (password) {
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  return await bcrypt.hash(password, salt);
};

UserSchema.methods.comparePassword = async function (enteredPassword) {
  // Caller must ensure password field was selected (e.g. .select('+password'))
  if (!this.password) return false;
  return await bcrypt.compare(enteredPassword, this.password);
};

UserSchema.methods.getProfile = function () {
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

UserSchema.methods.logLogin = function (ipAddress, userAgent, status = 'success') {
  this.loginHistory.push({
    date: new Date(),
    ipAddress,
    userAgent,
    status,
  });

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
    if (this.loginAttempts >= 5) {
      this.accountLocked = true;
      this.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
    }
  }

  return this.save();
};

UserSchema.methods.logActivity = function (action, resource, details = {}, ipAddress = null) {
  this.activityLog.push({ action, resource, timestamp: new Date(), ipAddress, details });
  if (this.activityLog.length > 100) {
    this.activityLog = this.activityLog.slice(-100);
  }
  this.lastActivityAt = new Date();
  return this.save();
};

// Consolidated refresh-token methods - one implementation only
UserSchema.methods.addRefreshToken = async function (token) {
  this.refreshTokens.push({ token, createdAt: new Date() });
  if (this.refreshTokens.length > 10) this.refreshTokens = this.refreshTokens.slice(-10);
  await this.save();
};

UserSchema.methods.removeRefreshToken = async function (token) {
  this.refreshTokens = (this.refreshTokens || []).filter(rt => rt.token !== token && rt !== token);
  await this.save();
  return this;
};

UserSchema.methods.updateLastActivity = function () {
  this.lastActivityAt = new Date();
  return this.save();
};

UserSchema.methods.updateSubscription = function (subscriptionData) {
  Object.assign(this.subscription, subscriptionData);
  return this.save();
};

UserSchema.methods.updatePreferences = function (preferencesData) {
  Object.assign(this.preferences, preferencesData);
  return this.save();
};

UserSchema.methods.suspendAccount = function (reason = null) {
  this.status = ACCOUNT_STATUS.SUSPENDED;
  if (reason) this.metadata = { ...this.metadata, suspensionReason: reason };
  return this.save();
};

UserSchema.methods.activateAccount = function () {
  this.status = ACCOUNT_STATUS.ACTIVE;
  return this.save();
};

UserSchema.methods.softDelete = function () {
  this.status = ACCOUNT_STATUS.DELETED;
  this.deletedAt = new Date();
  return this.save();
};

UserSchema.methods.verifyEmail = function () {
  this.isEmailVerified = true;
  this.emailVerificationToken = undefined;
  this.emailVerificationExpires = undefined;
  return this.save();
};

UserSchema.methods.verifyPhone = function () {
  this.isPhoneVerified = true;
  this.phoneVerificationToken = undefined;
  this.phoneVerificationExpires = undefined;
  return this.save();
};

UserSchema.methods.updateStats = function (expenseCount, reminderCount, budgetCount, totalSpent) {
  this.totalExpenses = expenseCount ?? this.totalExpenses;
  this.totalReminders = reminderCount ?? this.totalReminders;
  this.totalBudgets = budgetCount ?? this.totalBudgets;
  this.totalSpent = totalSpent ?? this.totalSpent;
  return this.save();
};

// ============= STATIC METHODS =============
UserSchema.statics.findByEmail = function (email) {
  return this.findOne({ email: email.toLowerCase() });
};

UserSchema.statics.findByRole = function (role) {
  return this.find({ role, status: ACCOUNT_STATUS.ACTIVE });
};

UserSchema.statics.getActiveUsers = function () {
  return this.find({ status: ACCOUNT_STATUS.ACTIVE });
};

UserSchema.statics.getPremiumUsers = function () {
  return this.find({ $or: [{ role: USER_ROLES.PREMIUM }, { 'subscription.status': 'active' }] });
};

UserSchema.statics.getExpiringSubscriptions = async function (daysThreshold = 7) {
  const thresholdDate = new Date();
  thresholdDate.setDate(thresholdDate.getDate() + daysThreshold);
  return this.find({ 'subscription.endDate': { $lte: thresholdDate, $gte: new Date() }, 'subscription.status': 'active' });
};

UserSchema.statics.getSuspendedUsers = function () {
  return this.find({ status: ACCOUNT_STATUS.SUSPENDED });
};

UserSchema.statics.getRecentlyActive = function (days = 7) {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - days);
  return this.find({ lastLogin: { $gte: dateThreshold }, status: ACCOUNT_STATUS.ACTIVE });
};

UserSchema.statics.getUserStatistics = async function () {
  const total = await this.countDocuments();
  const active = await this.countDocuments({ status: ACCOUNT_STATUS.ACTIVE });
  const premium = await this.countDocuments({ role: USER_ROLES.PREMIUM });
  const suspended = await this.countDocuments({ status: ACCOUNT_STATUS.SUSPENDED });
  const emailVerified = await this.countDocuments({ isEmailVerified: true });

  const totalSpent = await this.aggregate([{ $group: { _id: null, total: { $sum: '$totalSpent' } } }]);
  return { total, active, premium, suspended, emailVerified, totalSpent: totalSpent[0]?.total || 0 };
};

UserSchema.statics.searchUsers = async function (searchTerm, { limit = 20, skip = 0 } = {}) {
  const regex = new RegExp(searchTerm, 'i');
  const query = { $or: [{ name: regex }, { email: regex }, { phone: regex }] };
  const total = await this.countDocuments(query);
  const results = await this.find(query).select('-password -refreshTokens -twoFactorSecret').skip(skip).limit(limit).lean();
  return { results, total };
};

// ============= MIDDLEWARE =============

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    this.password = await bcrypt.hash(this.password, salt);
    this.passwordChangedAt = new Date();
    next();
  } catch (error) {
    next(error);
  }
});

// Avoid mutating saved doc in post('save'); toJSON transform handles API output
// UserSchema.post('save', ...) removed to avoid unexpected in-memory mutation

// ============= JSON OUTPUT OPTIONS =============
UserSchema.set('toJSON', {
  virtuals: true,
  transform: function (doc, ret) {
    delete ret.__v;
    delete ret.password;
    delete ret.refreshTokens;
    delete ret.twoFactorSecret;
    delete ret.twoFactorBackupCodes;
    delete ret.passwordResetToken;
    delete ret.emailVerificationToken;
    delete ret.phoneVerificationToken;
    return ret;
  },
});

UserSchema.set('toObject', { virtuals: true });

// ============= EXPORT =============
const UserModel = mongoose.model('User', UserSchema);
UserModel.USER_ROLES = USER_ROLES;
UserModel.ACCOUNT_STATUS = ACCOUNT_STATUS;
UserModel.NOTIFICATION_PREFERENCES = NOTIFICATION_PREFERENCES;
module.exports = UserModel;
