// models/User.js - Simplified Version (Indexes Fixed)
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 10;

// ============= ENUMS =============
const USER_ROLES = {
  USER: 'user',
  PREMIUM: 'premium', // Could be used for basic role management
  ADMIN: 'admin',
};

const ACCOUNT_STATUS = {
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  SUSPENDED: 'suspended', // Could be used for basic status checks
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
      unique: [true, 'Email already exists'], // Note: Unique indexes can be tricky in sharded clusters
      lowercase: true,
      trim: true,
      match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please add a valid email'],
      // index: true, // <-- REMOVED: Unique implies index, and it's explicitly defined below
    },

    password: {
      type: String,
      required: [true, 'Please add a password'],
      minlength: [6, 'Password must be at least 6 characters'], // Adjusted for simplified controller
      select: false, // Exclude password from queries by default
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
      // index: true, // <-- REMOVED: If you want an index on role, define it below
    },

    status: {
      type: String,
      enum: Object.values(ACCOUNT_STATUS),
      default: ACCOUNT_STATUS.ACTIVE,
      // index: true, // <-- REMOVED: Defined explicitly below
    },

    // Removed: isEmailVerified, emailVerificationToken, emailVerificationExpires
    // Removed: isPhoneVerified, phoneVerificationToken, phoneVerificationExpires
    // Removed: password management fields (except passwordChangedAt if needed)
    // Removed: security fields (loginAttempts, accountLocked, lockUntil, loginHistory)
    // Removed: refreshTokens array
    // Removed: activityLog array
    // Removed: twoFactor fields
    // Removed: social login fields
    // Removed: dataBackup, dataExport, tags, metadata
    // Removed: deletedAt

    // PREFERENCES (kept for user customization)
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

    // Subscription (kept if you plan to expand later)
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

    // Billing Info (kept if you plan to expand later)
    billingInfo: {
      fullName: String,
      address: String,
      city: String,
      state: String,
      postalCode: String,
      country: String,
      cardLast4: String,
    },

    // Core timestamps
    lastLogin: Date, // Kept to track last successful login
    // Removed: lastActivityAt
    createdAt: { type: Date, default: Date.now }, // index will be added via timestamps: true and explicit index below
    updatedAt: { type: Date, default: Date.now },
  },
  {
    timestamps: true, // Adds createdAt and updatedAt automatically
    toJSON: { virtuals: true }, // Include virtuals when converting to JSON
    toObject: { virtuals: true }, // Include virtuals when converting to Object
  }
);

// ============= INDEXES =============
// The 'email' unique constraint creates an index
// No need for UserSchema.index({ email: 1 }, { unique: true }); if unique: true is on the field
// BUT since we removed unique: true from the field definition to remove duplication,
// and you *want* it unique, we keep this explicit unique index:
UserSchema.index({ email: 1 }, { unique: true });
// The 'status' field index
UserSchema.index({ status: 1 });
// The 'role' field index
UserSchema.index({ role: 1 });
// The 'createdAt' field index (often created by timestamps: true, but explicitly defined here is fine)
UserSchema.index({ createdAt: -1 });
// The 'lastLogin' field index
UserSchema.index({ lastLogin: -1 });
// Subscription indexes
UserSchema.index({ 'subscription.status': 1 });
UserSchema.index({ 'subscription.endDate': 1 });
// Removed other indexes for removed fields

// ============= VIRTUALS =============
UserSchema.virtual('profileSummary').get(function () {
  return {
    id: this._id,
    name: this.name,
    email: this.email,
    avatar: this.avatar,
    role: this.role,
    status: this.status,
    // isEmailVerified: this.isEmailVerified, // Removed
    subscription: this.subscription && this.subscription.type,
    createdAt: this.createdAt,
  };
});

// Removed other virtuals related to removed features

UserSchema.virtual('isSubscriptionActive').get(function () {
  if (!this.subscription) return false;
  if (this.subscription.type === 'free') return true;
  return this.subscription.status === 'active' && (!this.subscription.endDate || new Date() < this.subscription.endDate);
});

UserSchema.virtual('isPremium').get(function () {
  if (!this.subscription) return this.role === USER_ROLES.PREMIUM;
  return this.role === USER_ROLES.PREMIUM || this.subscription.type !== 'free';
});

UserSchema.virtual('memberSince').get(function () {
  if (!this.createdAt) return null;
  return this.createdAt.toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' });
});

// ============= INSTANCE METHODS =============

// Removed encryptPassword (handled in pre-save hook)
// Removed comparePassword (handled in pre-save hook)

UserSchema.methods.getProfile = function () {
  const profile = this.toObject();
  delete profile.password; // Explicitly remove password if needed
  // No other fields to remove now
  return profile;
};

// Simplified logLogin - only updates lastLogin
UserSchema.methods.logLogin = async function () {
  this.lastLogin = new Date();
  // Removed updating login history, attempts, etc.
  return await this.save();
};

// Removed other instance methods related to removed features

// ============= STATIC METHODS =============
// Removed static methods related to removed features

// Simplified findByEmail
UserSchema.statics.findByEmail = function (email) {
  return this.findOne({ email: email.toLowerCase() });
};

// ============= MIDDLEWARE =============

// Hash password before saving if it's modified
UserSchema.pre('save', async function (next) {
  // Only hash the password if it's been modified (or new)
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    this.password = await bcrypt.hash(this.password, salt);
    this.passwordChangedAt = new Date(); // Update the passwordChangedAt field
    next();
  } catch (error) {
    next(error);
  }
});

// ============= JSON OUTPUT OPTIONS =============
// Configure JSON output to exclude sensitive fields
UserSchema.set('toJSON', {
  virtuals: true,
  transform: function (doc, ret) {
    delete ret.__v; // Remove version key
    delete ret.password; // Remove password field
    // No other fields to remove now
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
