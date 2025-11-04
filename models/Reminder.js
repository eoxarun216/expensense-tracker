// File: models/Reminder.js

const mongoose = require('mongoose');

// ============= ENUMS =============

const REMINDER_TYPES = {
  EMI: 'EMI',
  MOBILE_RECHARGE: 'Mobile Recharge',
  TV_RECHARGE: 'TV Recharge',
  UTILITY_BILL: 'Utility Bill',
  CREDIT_CARD: 'Credit Card',
  INSURANCE: 'Insurance',
  RENT: 'Rent',
  SUBSCRIPTION: 'Subscription',
  LOAN_PAYMENT: 'Loan Payment',
  INVESTMENT: 'Investment',
  CUSTOM: 'Custom',
};

const REMINDER_FREQUENCIES = {
  ONE_TIME: 'One-time',
  DAILY: 'Daily',
  WEEKLY: 'Weekly',
  BIWEEKLY: 'Bi-weekly',
  MONTHLY: 'Monthly',
  QUARTERLY: 'Quarterly',
  YEARLY: 'Yearly',
  CUSTOM: 'Custom',
};

const REMINDER_STATUS = {
  DRAFT: 'draft',
  ACTIVE: 'active',
  UPCOMING: 'upcoming',
  DUE: 'due',
  OVERDUE: 'overdue',
  PAID: 'paid',
  COMPLETED: 'completed',
  SKIPPED: 'skipped',
  CANCELLED: 'cancelled',
  PAUSED: 'paused',
};

const NOTIFICATION_PRIORITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

const NOTIFICATION_CHANNELS = {
  IN_APP: 'inApp',
  PUSH: 'push',
  EMAIL: 'email',
  SMS: 'sms',
  ALL: 'all',
};

// ============= REMINDER SCHEMA =============

const reminderSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
      index: true,
    },

    // Link to expense created from this reminder
    expenseId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Expense',
      default: null,
      index: true,
    },

    title: {
      type: String,
      required: [true, 'Title is required'],
      trim: true,
      maxlength: [100, 'Title cannot exceed 100 characters'],
      minlength: [1, 'Title must have at least 1 character'],
    },

    description: {
      type: String,
      trim: true,
      maxlength: [500, 'Description cannot exceed 500 characters'],
    },

    type: {
      type: String,
      enum: {
        values: Object.values(REMINDER_TYPES),
        message: 'Invalid reminder type',
      },
      required: [true, 'Reminder type is required'],
      index: true,
    },

    amount: {
      type: Number,
      required: [true, 'Amount is required'],
      min: [0, 'Amount must be non-negative'],
      max: [999999999.99, 'Amount exceeds maximum allowed'],
      validate: {
        validator: function(value) {
          return value > 0;
        },
        message: 'Amount must be greater than 0',
      },
    },

    dueDate: {
      type: Date,
      required: [true, 'Due date is required'],
      index: true,
    },

    frequency: {
      type: String,
      enum: {
        values: Object.values(REMINDER_FREQUENCIES),
        message: 'Invalid frequency',
      },
      default: REMINDER_FREQUENCIES.MONTHLY,
    },

    status: {
      type: String,
      enum: {
        values: Object.values(REMINDER_STATUS),
        message: 'Invalid status',
      },
      default: REMINDER_STATUS.ACTIVE,
      index: true,
    },

    priority: {
      type: String,
      enum: {
        values: Object.values(NOTIFICATION_PRIORITY),
        message: 'Invalid priority',
      },
      default: NOTIFICATION_PRIORITY.MEDIUM,
    },

    // ============= NOTIFICATION SETTINGS =============

    remindDaysBefore: {
      type: Number,
      default: 2,
      min: [0, 'Remind days before cannot be negative'],
      max: [365, 'Remind days before cannot exceed 365'],
    },

    notificationEnabled: {
      type: Boolean,
      default: true,
    },

    notificationChannel: {
      type: String,
      enum: {
        values: Object.values(NOTIFICATION_CHANNELS),
        message: 'Invalid notification channel',
      },
      default: NOTIFICATION_CHANNELS.ALL,
    },

    sendMultipleReminders: {
      type: Boolean,
      default: false,
    },

    multipleReminderDays: {
      type: [Number],
      default: [],
      validate: {
        validator: function(value) {
          return Array.isArray(value) && value.length <= 10;
        },
        message: 'Multiple reminders cannot exceed 10',
      },
    },

    // ============= RECURRING SETTINGS =============

    isRecurring: {
      type: Boolean,
      default: false,
    },

    recurrencePattern: {
      frequency: {
        type: String,
        enum: Object.values(REMINDER_FREQUENCIES),
      },
      interval: {
        type: Number,
        default: 1,
        min: 1,
      },
      endDate: Date,
      maxOccurrences: Number,
    },

    occurrenceCount: {
      type: Number,
      default: 0,
      min: 0,
    },

    nextDueDate: Date,

    // ============= PAYMENT TRACKING =============

    notes: {
      type: String,
      trim: true,
      maxlength: [1000, 'Notes cannot exceed 1000 characters'],
      default: '',
    },

    paymentLink: {
      type: String,
      trim: true,
    },

    paymentMethod: {
      type: String,
      enum: ['cash', 'credit_card', 'debit_card', 'upi', 'bank_transfer', 'wallet', 'other'],
    },

    icon: {
      type: String,
      trim: true,
      default: 'bell',
    },

    color: {
      type: String,
      default: '#3498db',
      match: [/^#[0-9A-Fa-f]{6}$/, 'Invalid color format'],
    },

    category: {
      type: String,
      trim: true,
    },

    vendor: {
      type: String,
      trim: true,
      maxlength: [100, 'Vendor name cannot exceed 100 characters'],
    },

    tags: {
      type: [String],
      default: [],
      validate: {
        validator: function(value) {
          return Array.isArray(value) && value.length <= 10;
        },
        message: 'Tags cannot exceed 10 items',
      },
    },

    // ============= PAYMENT HISTORY =============

    totalPaidAmount: {
      type: Number,
      default: 0,
      min: 0,
    },

    paidDates: [Date],

    lastPaidAt: Date,

    lastPaidAmount: Number,

    // ============= TRACKING FIELDS =============

    isNotified: {
      type: Boolean,
      default: false,
    },

    lastNotifiedAt: Date,

    notificationCount: {
      type: Number,
      default: 0,
      min: 0,
    },

    attachment: {
      url: String,
      fileName: String,
      uploadedAt: Date,
    },

    // Audit fields
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: function() {
        return this.userId;
      },
    },

    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },

    deletedAt: {
      type: Date,
      default: null,
    },

    deletedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ============= INDEXES =============

reminderSchema.index({ userId: 1, dueDate: 1 });
reminderSchema.index({ userId: 1, status: 1 });
reminderSchema.index({ userId: 1, type: 1 });
reminderSchema.index({ userId: 1, priority: 1 });
reminderSchema.index({ expenseId: 1 });
reminderSchema.index({ userId: 1, createdAt: -1 });
reminderSchema.index({ userId: 1, isRecurring: 1 });
reminderSchema.index({ userId: 1, nextDueDate: 1 });
reminderSchema.index({ userId: 1, deletedAt: 1 });
// Compound indexes
reminderSchema.index({ userId: 1, status: 1, dueDate: 1 });
reminderSchema.index({ userId: 1, isRecurring: 1, nextDueDate: 1 });
reminderSchema.index({ userId: 1, priority: 1, status: 1 });

// ============= VIRTUAL FIELDS =============

/**
 * Check if reminder is overdue
 */
reminderSchema.virtual('isOverdue').get(function() {
  return new Date() > this.dueDate && this.status !== REMINDER_STATUS.PAID && this.status !== REMINDER_STATUS.COMPLETED;
});

/**
 * Check if reminder is due soon (within remindDaysBefore)
 */
reminderSchema.virtual('isDueSoon').get(function() {
  const today = new Date();
  const remindDate = new Date(this.dueDate);
  remindDate.setDate(remindDate.getDate() - this.remindDaysBefore);
  return today >= remindDate && today <= this.dueDate;
});

/**
 * Get days until due
 */
reminderSchema.virtual('daysUntilDue').get(function() {
  const now = new Date();
  const due = new Date(this.dueDate);
  const timeDiff = due - now;
  return Math.ceil(timeDiff / (1000 * 60 * 60 * 24));
});

/**
 * Get days overdue
 */
reminderSchema.virtual('daysOverdue').get(function() {
  if (!this.isOverdue) return 0;
  const now = new Date();
  const due = new Date(this.dueDate);
  const timeDiff = now - due;
  return Math.floor(timeDiff / (1000 * 60 * 60 * 24));
});

/**
 * Check if reminder should notify
 */
reminderSchema.virtual('shouldNotify').get(function() {
  if (!this.notificationEnabled || this.status === REMINDER_STATUS.PAID) return false;

  if (this.sendMultipleReminders && this.multipleReminderDays.length > 0) {
    return this.multipleReminderDays.includes(this.daysUntilDue) && this.daysUntilDue >= 0;
  }

  return this.daysUntilDue <= this.remindDaysBefore && this.daysUntilDue >= 0;
});

/**
 * Get formatted due date
 */
reminderSchema.virtual('formattedDueDate').get(function() {
  return new Date(this.dueDate).toLocaleDateString('en-IN', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
});

/**
 * Get formatted amount
 */
reminderSchema.virtual('formattedAmount').get(function() {
  return `₹${this.amount.toFixed(2)}`;
});

/**
 * Check if deleted
 */
reminderSchema.virtual('isDeleted').get(function() {
  return this.deletedAt !== null;
});

/**
 * Get status display
 */
reminderSchema.virtual('statusDisplay').get(function() {
  if (this.status === REMINDER_STATUS.PAID) return 'Paid';
  if (this.isOverdue) return 'Overdue';
  if (this.isDueSoon) return 'Due Soon';
  return 'Upcoming';
});

/**
 * Get remaining amount to pay
 */
reminderSchema.virtual('remainingAmount').get(function() {
  return Math.max(0, this.amount - this.totalPaidAmount);
});

/**
 * Check if fully paid
 */
reminderSchema.virtual('isFullyPaid').get(function() {
  return this.totalPaidAmount >= this.amount;
});

// ============= INSTANCE METHODS =============

/**
 * Mark reminder as paid
 */
reminderSchema.methods.markAsPaid = function(amount = null, userId = null) {
  const paidAmount = amount || this.amount;

  if (paidAmount < 0) {
    throw new Error('Paid amount cannot be negative');
  }

  this.totalPaidAmount += paidAmount;
  this.lastPaidAt = new Date();
  this.lastPaidAmount = paidAmount;
  this.paidDates.push(new Date());
  this.notificationCount = 0;
  this.isNotified = false;

  // Mark as paid if fully paid
  if (this.totalPaidAmount >= this.amount) {
    this.status = REMINDER_STATUS.COMPLETED;
  }

  if (userId) {
    this.updatedBy = userId;
  }

  return this.save();
};

/**
 * Mark as partially paid
 */
reminderSchema.methods.markAsPartiallyPaid = function(amount, userId = null) {
  if (amount <= 0 || amount > this.amount) {
    throw new Error('Partial payment amount must be between 0 and reminder amount');
  }

  this.totalPaidAmount += amount;
  this.lastPaidAt = new Date();
  this.lastPaidAmount = amount;
  this.paidDates.push(new Date());
  this.status = REMINDER_STATUS.ACTIVE;

  if (userId) {
    this.updatedBy = userId;
  }

  return this.save();
};

/**
 * Revert payment
 */
reminderSchema.methods.revertPayment = function(userId = null) {
  if (this.paidDates.length === 0) {
    throw new Error('No payments to revert');
  }

  this.paidDates.pop();
  this.totalPaidAmount -= this.lastPaidAmount || 0;
  this.status = REMINDER_STATUS.ACTIVE;

  if (userId) {
    this.updatedBy = userId;
  }

  return this.save();
};

/**
 * Skip reminder
 */
reminderSchema.methods.skipReminder = function(userId = null) {
  this.status = REMINDER_STATUS.SKIPPED;

  if (userId) {
    this.updatedBy = userId;
  }

  return this.save();
};

/**
 * Pause reminder
 */
reminderSchema.methods.pauseReminder = function(userId = null) {
  this.status = REMINDER_STATUS.PAUSED;

  if (userId) {
    this.updatedBy = userId;
  }

  return this.save();
};

/**
 * Resume reminder
 */
reminderSchema.methods.resumeReminder = function(userId = null) {
  this.status = REMINDER_STATUS.ACTIVE;

  if (userId) {
    this.updatedBy = userId;
  }

  return this.save();
};

/**
 * Calculate next due date for recurring reminders
 */
reminderSchema.methods.calculateNextDueDate = function() {
  if (!this.isRecurring || !this.recurrencePattern) {
    return null;
  }

  const nextDate = new Date(this.dueDate);
  const { frequency, interval } = this.recurrencePattern;

  switch (frequency) {
    case REMINDER_FREQUENCIES.DAILY:
      nextDate.setDate(nextDate.getDate() + (interval || 1));
      break;
    case REMINDER_FREQUENCIES.WEEKLY:
      nextDate.setDate(nextDate.getDate() + (interval || 1) * 7);
      break;
    case REMINDER_FREQUENCIES.BIWEEKLY:
      nextDate.setDate(nextDate.getDate() + (interval || 1) * 14);
      break;
    case REMINDER_FREQUENCIES.MONTHLY:
      nextDate.setMonth(nextDate.getMonth() + (interval || 1));
      break;
    case REMINDER_FREQUENCIES.QUARTERLY:
      nextDate.setMonth(nextDate.getMonth() + (interval || 1) * 3);
      break;
    case REMINDER_FREQUENCIES.YEARLY:
      nextDate.setFullYear(nextDate.getFullYear() + (interval || 1));
      break;
    case REMINDER_FREQUENCIES.CUSTOM:
      nextDate.setDate(nextDate.getDate() + (interval || 1));
      break;
    default:
      return null;
  }

  // Check if exceeds end date or max occurrences
  if (this.recurrencePattern.endDate && nextDate > this.recurrencePattern.endDate) {
    return null;
  }

  if (
    this.recurrencePattern.maxOccurrences &&
    this.occurrenceCount >= this.recurrencePattern.maxOccurrences
  ) {
    return null;
  }

  return nextDate;
};

/**
 * Get reminder summary
 */
reminderSchema.methods.getSummary = function() {
  return {
    id: this._id,
    title: this.title,
    type: this.type,
    amount: this.amount,
    formattedAmount: this.formattedAmount,
    dueDate: this.dueDate,
    formattedDueDate: this.formattedDueDate,
    status: this.status,
    statusDisplay: this.statusDisplay,
    priority: this.priority,
    daysUntilDue: this.daysUntilDue,
    isOverdue: this.isOverdue,
    isDueSoon: this.isDueSoon,
    shouldNotify: this.shouldNotify,
    totalPaidAmount: this.totalPaidAmount,
    remainingAmount: this.remainingAmount,
    isFullyPaid: this.isFullyPaid,
    frequency: this.frequency,
    isRecurring: this.isRecurring,
    vendor: this.vendor,
    category: this.category,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
};

/**
 * Soft delete reminder
 */
reminderSchema.methods.softDelete = function(userId = null) {
  this.deletedAt = new Date();
  if (userId) {
    this.deletedBy = userId;
  }
  return this.save();
};

/**
 * Restore deleted reminder
 */
reminderSchema.methods.restore = function(userId = null) {
  this.deletedAt = null;
  this.deletedBy = null;
  if (userId) {
    this.updatedBy = userId;
  }
  return this.save();
};

/**
 * Link to expense
 */
reminderSchema.methods.linkToExpense = function(expenseId, userId = null) {
  this.expenseId = expenseId;
  if (userId) {
    this.updatedBy = userId;
  }
  return this.save();
};

/**
 * Mark as notified
 */
reminderSchema.methods.markAsNotified = function() {
  this.isNotified = true;
  this.lastNotifiedAt = new Date();
  this.notificationCount = (this.notificationCount || 0) + 1;
  return this.save();
};

// ============= STATIC METHODS =============

/**
 * Get all active reminders for user
 */
reminderSchema.statics.getActive = function(userId) {
  return this.find({
    userId,
    status: { $in: [REMINDER_STATUS.ACTIVE, REMINDER_STATUS.UPCOMING, REMINDER_STATUS.DUE, REMINDER_STATUS.OVERDUE] },
    deletedAt: null,
  }).sort({ dueDate: 1 });
};

/**
 * Get overdue reminders
 */
reminderSchema.statics.getOverdue = function(userId) {
  const now = new Date();
  return this.find({
    userId,
    dueDate: { $lt: now },
    status: { $ne: REMINDER_STATUS.PAID },
    deletedAt: null,
  }).sort({ dueDate: 1 });
};

/**
 * Get upcoming reminders
 */
reminderSchema.statics.getUpcoming = function(userId, days = 7) {
  const now = new Date();
  const futureDate = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);

  return this.find({
    userId,
    dueDate: { $gte: now, $lte: futureDate },
    status: { $ne: REMINDER_STATUS.PAID },
    deletedAt: null,
  }).sort({ dueDate: 1 });
};

/**
 * Get paid reminders
 */
reminderSchema.statics.getPaid = function(userId) {
  return this.find({
    userId,
    status: REMINDER_STATUS.PAID,
    deletedAt: null,
  }).sort({ lastPaidAt: -1 });
};

/**
 * Get reminders due today
 */
reminderSchema.statics.getDueToday = function(userId) {
  const today = new Date();
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);

  return this.find({
    userId,
    dueDate: { $gte: today, $lt: tomorrow },
    status: { $ne: REMINDER_STATUS.PAID },
    deletedAt: null,
  });
};

/**
 * Get reminders by type
 */
reminderSchema.statics.getByType = function(userId, type) {
  return this.find({
    userId,
    type,
    deletedAt: null,
  }).sort({ dueDate: 1 });
};

/**
 * Get reminders by priority
 */
reminderSchema.statics.getByPriority = function(userId, priority) {
  return this.find({
    userId,
    priority,
    status: { $ne: REMINDER_STATUS.PAID },
    deletedAt: null,
  }).sort({ dueDate: 1 });
};

/**
 * Get recurring reminders
 */
reminderSchema.statics.getRecurring = function(userId) {
  return this.find({
    userId,
    isRecurring: true,
    deletedAt: null,
  }).sort({ dueDate: 1 });
};

/**
 * Get reminders needing notification
 */
reminderSchema.statics.getNeedingNotification = function(userId) {
  return this.find({
    userId,
    notificationEnabled: true,
    status: { $ne: REMINDER_STATUS.PAID },
    deletedAt: null,
  }).then(reminders => {
    return reminders.filter(r => r.shouldNotify);
  });
};

/**
 * Get statistics for user
 */
reminderSchema.statics.getStatistics = async function(userId) {
  const total = await this.countDocuments({ userId, deletedAt: null });
  const active = await this.countDocuments({
    userId,
    status: { $in: [REMINDER_STATUS.ACTIVE, REMINDER_STATUS.UPCOMING] },
    deletedAt: null,
  });
  const overdue = await this.countDocuments({
    userId,
    dueDate: { $lt: new Date() },
    status: { $ne: REMINDER_STATUS.PAID },
    deletedAt: null,
  });
  const paid = await this.countDocuments({
    userId,
    status: REMINDER_STATUS.PAID,
    deletedAt: null,
  });

  const totalAmount = await this.aggregate([
    { $match: { userId: mongoose.Types.ObjectId(userId), deletedAt: null } },
    { $group: { _id: null, total: { $sum: '$amount' } } },
  ]);

  return {
    total,
    active,
    overdue,
    paid,
    totalAmount: totalAmount[0]?.total || 0,
  };
};

/**
 * Get breakdown by type
 */
reminderSchema.statics.getTypeBreakdown = async function(userId) {
  return this.aggregate([
    { $match: { userId: mongoose.Types.ObjectId(userId), deletedAt: null } },
    {
      $group: {
        _id: '$type',
        count: { $sum: 1 },
        totalAmount: { $sum: '$amount' },
      },
    },
    { $sort: { totalAmount: -1 } },
  ]);
};

/**
 * Search reminders
 */
reminderSchema.statics.searchReminders = async function(userId, searchTerm, { limit = 20, skip = 0 } = {}) {
  const regex = new RegExp(searchTerm, 'i');
  const query = {
    userId,
    deletedAt: null,
    $or: [{ title: regex }, { description: regex }, { vendor: regex }, { category: regex }],
  };

  const total = await this.countDocuments(query);
  const results = await this.find(query)
    .sort({ dueDate: 1 })
    .skip(skip)
    .limit(limit)
    .lean();

  return { results, total };
};

// ============= MIDDLEWARE =============

/**
 * Pre-save: Validate and calculate next due date
 */
reminderSchema.pre('save', function(next) {
  // Validate due date
  if (this.dueDate < new Date()) {
    if (this.status === REMINDER_STATUS.ACTIVE) {
      this.status = REMINDER_STATUS.OVERDUE;
    }
  }

  // Calculate next due date for recurring reminders
  if (this.isRecurring && this.frequency !== REMINDER_FREQUENCIES.ONE_TIME) {
    this.nextDueDate = this.calculateNextDueDate();
  }

  // Validate amount
  if (this.amount <= 0) {
    throw new Error('Amount must be greater than 0');
  }

  next();
});

/**
 * Post-save logging
 */
reminderSchema.post('save', function(doc) {
  console.log(`Reminder ${doc._id} saved successfully`);
});

// ============= JSON OUTPUT OPTIONS =============

reminderSchema.set('toJSON', {
  virtuals: true,
  transform: function(doc, ret) {
    delete ret.__v;
    if (ret.deletedAt) {
      delete ret.deletedAt;
      delete ret.deletedBy;
    }
    return ret;
  },
});

reminderSchema.set('toObject', { virtuals: true });

// ============= EXPORT =============

module.exports = mongoose.model('Reminder', reminderSchema);

// ============= EXPORT ENUMS & CONSTANTS =============

module.exports.REMINDER_TYPES = REMINDER_TYPES;
module.exports.REMINDER_FREQUENCIES = REMINDER_FREQUENCIES;
module.exports.REMINDER_STATUS = REMINDER_STATUS;
module.exports.NOTIFICATION_PRIORITY = NOTIFICATION_PRIORITY;
module.exports.NOTIFICATION_CHANNELS = NOTIFICATION_CHANNELS;
