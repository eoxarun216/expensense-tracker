// File: models/Budget.js

const mongoose = require('mongoose');

// ============= ENUMS =============

const BUDGET_TYPES = {
  EXPENSE: 'expense',
  INCOME: 'income',
};

const BUDGET_PERIODS = {
  WEEKLY: 'weekly',
  MONTHLY: 'monthly',
  YEARLY: 'yearly',
};

const INCOME_SOURCES = {
  PERSONAL: 'personal',
  FAMILY: 'family',
  BUSINESS: 'business',
  INVESTMENT: 'investment',
  ADDITIONAL: 'additional',
  OTHER: 'other',
};

const EXPENSE_CATEGORIES = [
  'Food',
  'Transportation',
  'Entertainment',
  'Utilities',
  'Healthcare',
  'Shopping',
  'Education',
  'Travel',
  'Dining',
  'Subscriptions',
  'Rent',
  'Insurance',
  'Savings',
  'Other',
];

// ============= BUDGET SCHEMA =============

const BudgetSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    category: {
      type: String,
      required: [true, 'Category is required'],
      trim: true,
      validate: {
        validator: function(value) {
          if (this.type === BUDGET_TYPES.EXPENSE) {
            return EXPENSE_CATEGORIES.includes(value);
          }
          return true;
        },
        message: 'Invalid expense category',
      },
    },
    type: {
      type: String,
      enum: {
        values: Object.values(BUDGET_TYPES),
        message: 'Type must be either "expense" or "income"',
      },
      default: BUDGET_TYPES.EXPENSE,
      required: true,
    },
    limit: {
      type: Number,
      required: [
        function() {
          return this.type === BUDGET_TYPES.EXPENSE;
        },
        'Limit is required for expense budgets',
      ],
      min: [0, 'Limit must be non-negative'],
      validate: {
        validator: function(value) {
          return value <= 999999999.99;
        },
        message: 'Limit exceeds maximum allowed amount',
      },
    },
    spent: {
      type: Number,
      default: 0.0,
      min: [0, 'Spent amount must be non-negative'],
      validate: {
        validator: function(value) {
          return value <= 999999999.99;
        },
        message: 'Spent amount exceeds maximum allowed',
      },
    },
    period: {
      type: String,
      enum: {
        values: Object.values(BUDGET_PERIODS),
        message: 'Period must be weekly, monthly, or yearly',
      },
      default: BUDGET_PERIODS.MONTHLY,
    },

    // ============= INCOME-SPECIFIC FIELDS =============

    incomeSource: {
      type: String,
      enum: {
        values: Object.values(INCOME_SOURCES),
        message: 'Invalid income source',
      },
      trim: true,
      required: [
        function() {
          return this.type === BUDGET_TYPES.INCOME;
        },
        'Income source is required for income entries',
      ],
    },
    incomeAmount: {
      type: Number,
      min: [0, 'Income amount must be non-negative'],
      required: [
        function() {
          return this.type === BUDGET_TYPES.INCOME;
        },
        'Income amount is required for income entries',
      ],
      validate: {
        validator: function(value) {
          if (this.type === BUDGET_TYPES.INCOME) {
            return value > 0 && value <= 999999999.99;
          }
          return true;
        },
        message: 'Income amount must be positive and not exceed maximum',
      },
    },

    // ============= ADDITIONAL FIELDS =============

    description: {
      type: String,
      trim: true,
      maxlength: [500, 'Description cannot exceed 500 characters'],
    },
    notes: {
      type: String,
      trim: true,
      maxlength: [1000, 'Notes cannot exceed 1000 characters'],
    },
    recurring: {
      type: Boolean,
      default: true,
    },
    active: {
      type: Boolean,
      default: true,
    },
    tags: {
      type: [String],
      default: [],
    },
    alertThreshold: {
      type: Number,
      default: 80,
      min: [0, 'Alert threshold must be non-negative'],
      max: [100, 'Alert threshold cannot exceed 100'],
    },
    notifyOnExceed: {
      type: Boolean,
      default: true,
    },
    color: {
      type: String,
      default: '#3498db',
      match: [/^#[0-9A-Fa-f]{6}$/, 'Invalid color format'],
    },
    icon: {
      type: String,
      default: 'default',
    },
    startDate: {
      type: Date,
      default: Date.now,
    },
    endDate: {
      type: Date,
      validate: {
        validator: function(value) {
          if (!value) return true;
          return value > this.startDate;
        },
        message: 'End date must be after start date',
      },
    },

    // ============= TRACKING FIELDS =============

    lastResetDate: Date,
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
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ============= INDEXES =============

BudgetSchema.index({ userId: 1, type: 1, period: 1 });
BudgetSchema.index({ userId: 1, category: 1 });
BudgetSchema.index({ userId: 1, incomeSource: 1 });
BudgetSchema.index({ userId: 1, active: 1 });
BudgetSchema.index({ userId: 1, createdAt: -1 });
BudgetSchema.index({ startDate: 1, endDate: 1 });

// ============= VIRTUAL FIELDS =============

BudgetSchema.virtual('isIncome').get(function() {
  return this.type === BUDGET_TYPES.INCOME;
});

BudgetSchema.virtual('isExpense').get(function() {
  return this.type === BUDGET_TYPES.EXPENSE;
});

BudgetSchema.virtual('effectiveAmount').get(function() {
  return this.type === BUDGET_TYPES.INCOME ? this.incomeAmount : this.spent;
});

BudgetSchema.virtual('usagePercentage').get(function() {
  if (this.type === BUDGET_TYPES.EXPENSE && this.limit > 0) {
    return (this.spent / this.limit) * 100;
  }
  return 0;
});

BudgetSchema.virtual('remaining').get(function() {
  if (this.type === BUDGET_TYPES.EXPENSE) {
    const rem = this.limit - this.spent;
    return rem > 0 ? rem : 0;
  }
  return 0;
});

BudgetSchema.virtual('status').get(function() {
  if (this.type === BUDGET_TYPES.INCOME) return 'income';

  const percentage = this.usagePercentage;
  if (percentage > 100) return 'exceeded';
  if (percentage >= this.alertThreshold) return 'warning';
  return 'safe';
});

BudgetSchema.virtual('daysRemaining').get(function() {
  if (!this.endDate) return null;
  const now = new Date();
  const timeDiff = this.endDate - now;
  return Math.ceil(timeDiff / (1000 * 60 * 60 * 24));
});

BudgetSchema.virtual('isExpired').get(function() {
  if (!this.endDate) return false;
  return new Date() > this.endDate;
});

// ============= INSTANCE METHODS =============

/**
 * Update spent amount for expense budgets
 */
BudgetSchema.methods.updateSpent = function(amount, userId) {
  if (this.type !== BUDGET_TYPES.EXPENSE) {
    throw new Error('Cannot update spent amount for income entries');
  }

  if (amount < 0) {
    throw new Error('Spent amount cannot be negative');
  }

  this.spent = amount;
  this.updatedBy = userId;
  return this.save();
};

/**
 * Add to spent amount
 */
BudgetSchema.methods.addSpent = function(amount, userId) {
  if (this.type !== BUDGET_TYPES.EXPENSE) {
    throw new Error('Cannot add spent amount to income entries');
  }

  if (amount < 0) {
    throw new Error('Amount must be positive');
  }

  this.spent += amount;
  this.updatedBy = userId;
  return this.save();
};

/**
 * Subtract from spent amount
 */
BudgetSchema.methods.subtractSpent = function(amount, userId) {
  if (this.type !== BUDGET_TYPES.EXPENSE) {
    throw new Error('Cannot subtract from income entries');
  }

  if (amount < 0) {
    throw new Error('Amount must be positive');
  }

  this.spent = Math.max(0, this.spent - amount);
  this.updatedBy = userId;
  return this.save();
};

/**
 * Update income amount for income budgets
 */
BudgetSchema.methods.updateIncome = function(amount, userId) {
  if (this.type !== BUDGET_TYPES.INCOME) {
    throw new Error('Cannot update income amount for expense entries');
  }

  if (amount <= 0) {
    throw new Error('Income amount must be positive');
  }

  this.incomeAmount = amount;
  this.updatedBy = userId;
  return this.save();
};

/**
 * Reset spent amount (typically at period start)
 */
BudgetSchema.methods.reset = function(userId) {
  if (this.type === BUDGET_TYPES.EXPENSE) {
    this.spent = 0;
    this.lastResetDate = new Date();
    this.updatedBy = userId;
    return this.save();
  }
  throw new Error('Cannot reset income entries');
};

/**
 * Check if budget exceeds limit
 */
BudgetSchema.methods.isExceeded = function() {
  if (this.type !== BUDGET_TYPES.EXPENSE) return false;
  return this.spent > this.limit;
};

/**
 * Check if budget is within warning threshold
 */
BudgetSchema.methods.isWarning = function() {
  if (this.type !== BUDGET_TYPES.EXPENSE) return false;
  const percentage = this.usagePercentage;
  return percentage >= this.alertThreshold && percentage <= 100;
};

/**
 * Get budget summary
 */
BudgetSchema.methods.getSummary = function() {
  return {
    id: this._id,
    userId: this.userId,
    category: this.category,
    type: this.type,
    period: this.period,
    ...(this.type === BUDGET_TYPES.EXPENSE
      ? {
          limit: this.limit,
          spent: this.spent,
          remaining: this.remaining,
          usagePercentage: this.usagePercentage,
          status: this.status,
        }
      : {
          incomeSource: this.incomeSource,
          incomeAmount: this.incomeAmount,
        }),
    active: this.active,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
};

// ============= STATIC METHODS =============

/**
 * Get all budgets for a user by type
 */
BudgetSchema.statics.getByType = function(userId, type) {
  return this.find({ userId, type, active: true }).sort({ createdAt: -1 });
};

/**
 * Get all income entries for a user
 */
BudgetSchema.statics.getIncomeByUser = function(userId) {
  return this.find({ userId, type: BUDGET_TYPES.INCOME, active: true }).sort({ createdAt: -1 });
};

/**
 * Get all expense budgets for a user
 */
BudgetSchema.statics.getExpensesByUser = function(userId) {
  return this.find({ userId, type: BUDGET_TYPES.EXPENSE, active: true }).sort({ createdAt: -1 });
};

/**
 * Get income by source
 */
BudgetSchema.statics.getIncomeBySource = function(userId, source) {
  return this.find({
    userId,
    type: BUDGET_TYPES.INCOME,
    incomeSource: source,
    active: true,
  });
};

/**
 * Get budgets by category
 */
BudgetSchema.statics.getByCategory = function(userId, category) {
  return this.find({ userId, category, type: BUDGET_TYPES.EXPENSE, active: true });
};

/**
 * Get budgets by period
 */
BudgetSchema.statics.getByPeriod = function(userId, period) {
  return this.find({ userId, period, active: true }).sort({ createdAt: -1 });
};

/**
 * Calculate total income
 */
BudgetSchema.statics.getTotalIncome = async function(userId, period = null) {
  const query = { userId, type: BUDGET_TYPES.INCOME, active: true };
  if (period) query.period = period;

  const result = await this.aggregate([
    { $match: query },
    { $group: { _id: null, total: { $sum: '$incomeAmount' } } },
  ]);

  return result.length > 0 ? result[0].total : 0;
};

/**
 * Calculate total expenses
 */
BudgetSchema.statics.getTotalExpenses = async function(userId, period = null) {
  const query = { userId, type: BUDGET_TYPES.EXPENSE, active: true };
  if (period) query.period = period;

  const result = await this.aggregate([
    { $match: query },
    { $group: { _id: null, total: { $sum: '$spent' } } },
  ]);

  return result.length > 0 ? result[0].total : 0;
};

/**
 * Calculate total budget limit
 */
BudgetSchema.statics.getTotalBudgetLimit = async function(userId, period = null) {
  const query = { userId, type: BUDGET_TYPES.EXPENSE, active: true };
  if (period) query.period = period;

  const result = await this.aggregate([
    { $match: query },
    { $group: { _id: null, total: { $sum: '$limit' } } },
  ]);

  return result.length > 0 ? result[0].total : 0;
};

/**
 * Calculate net income
 */
BudgetSchema.statics.getNetIncome = async function(userId, period = null) {
  const totalIncome = await this.getTotalIncome(userId, period);
  const totalExpenses = await this.getTotalExpenses(userId, period);
  return totalIncome - totalExpenses;
};

/**
 * Get income breakdown by source
 */
BudgetSchema.statics.getIncomeBreakdown = async function(userId, period = null) {
  const query = { userId, type: BUDGET_TYPES.INCOME, active: true };
  if (period) query.period = period;

  return this.aggregate([
    { $match: query },
    {
      $group: {
        _id: '$incomeSource',
        total: { $sum: '$incomeAmount' },
        count: { $sum: 1 },
        percentage: { $avg: { $literal: 1 } },
      },
    },
    {
      $project: {
        _id: 0,
        source: '$_id',
        total: 1,
        count: 1,
      },
    },
    { $sort: { total: -1 } },
  ]);
};

/**
 * Get expense breakdown by category
 */
BudgetSchema.statics.getExpenseBreakdown = async function(userId, period = null) {
  const query = { userId, type: BUDGET_TYPES.EXPENSE, active: true };
  if (period) query.period = period;

  return this.aggregate([
    { $match: query },
    {
      $group: {
        _id: '$category',
        totalSpent: { $sum: '$spent' },
        totalLimit: { $sum: '$limit' },
        count: { $sum: 1 },
      },
    },
    {
      $project: {
        _id: 0,
        category: '$_id',
        totalSpent: 1,
        totalLimit: 1,
        count: 1,
        remaining: { $subtract: ['$totalLimit', '$totalSpent'] },
        usagePercentage: {
          $cond: [
            { $eq: ['$totalLimit', 0] },
            0,
            { $multiply: [{ $divide: ['$totalSpent', '$totalLimit'] }, 100] },
          ],
        },
      },
    },
    { $sort: { usagePercentage: -1 } },
  ]);
};

/**
 * Get financial health score
 */
BudgetSchema.statics.getFinancialHealth = async function(userId, period = null) {
  const totalIncome = await this.getTotalIncome(userId, period);
  const totalExpenses = await this.getTotalExpenses(userId, period);

  if (totalIncome === 0) {
    return {
      score: 0,
      status: 'no_income',
      totalIncome: 0,
      totalExpenses,
      netIncome: -totalExpenses,
      savingsRate: 0,
      expenseRatio: Infinity,
    };
  }

  const expenseRatio = totalExpenses / totalIncome;
  const savingsRate = ((totalIncome - totalExpenses) / totalIncome) * 100;

  let score, status;
  if (expenseRatio >= 1.0) {
    score = 0;
    status = 'poor';
  } else if (expenseRatio >= 0.9) {
    score = 30;
    status = 'bad';
  } else if (expenseRatio >= 0.7) {
    score = 60;
    status = 'fair';
  } else if (expenseRatio >= 0.5) {
    score = 80;
    status = 'good';
  } else {
    score = 100;
    status = 'excellent';
  }

  return {
    score,
    status,
    totalIncome,
    totalExpenses,
    netIncome: totalIncome - totalExpenses,
    savingsRate: parseFloat(savingsRate.toFixed(2)),
    expenseRatio: parseFloat(expenseRatio.toFixed(2)),
  };
};

/**
 * Get budgets with warnings
 */
BudgetSchema.statics.getWarningBudgets = async function(userId, period = null) {
  const query = {
    userId,
    type: BUDGET_TYPES.EXPENSE,
    active: true,
    $expr: {
      $gte: [
        { $multiply: [{ $divide: ['$spent', '$limit'] }, 100] },
        { $ifNull: ['$alertThreshold', 80] },
      ],
    },
  };

  return this.find(query).sort({ spent: -1 });
};

/**
 * Get exceeded budgets
 */
BudgetSchema.statics.getExceededBudgets = async function(userId, period = null) {
  const query = {
    userId,
    type: BUDGET_TYPES.EXPENSE,
    active: true,
    $expr: { $gt: ['$spent', '$limit'] },
  };

  return this.find(query).sort({ spent: -1 });
};

/**
 * Calculate category summary
 */
BudgetSchema.statics.getCategorySummary = async function(userId) {
  const breakdown = await this.getExpenseBreakdown(userId);
  const summary = {};

  for (const item of breakdown) {
    summary[item.category] = {
      spent: item.totalSpent,
      limit: item.totalLimit,
      remaining: item.remaining,
      usagePercentage: item.usagePercentage,
      status:
        item.usagePercentage > 100
          ? 'exceeded'
          : item.usagePercentage >= 80
          ? 'warning'
          : 'safe',
    };
  }

  return summary;
};

// ============= MIDDLEWARE =============

/**
 * Pre-save validation and data integrity
 */
BudgetSchema.pre('save', function(next) {
  // For income entries
  if (this.type === BUDGET_TYPES.INCOME) {
    this.spent = 0;
    this.limit = 0;
  }

  // For expense entries
  if (this.type === BUDGET_TYPES.EXPENSE) {
    this.incomeAmount = undefined;
    this.incomeSource = undefined;
  }

  // Validate limit is not zero for expenses
  if (this.type === BUDGET_TYPES.EXPENSE && this.limit <= 0) {
    throw new Error('Budget limit must be greater than 0 for expense entries');
  }

  next();
});

/**
 * Post-save hook for logging
 */
BudgetSchema.post('save', function(doc) {
  console.log(`Budget ${doc._id} saved successfully`);
});

// ============= JSON OUTPUT OPTIONS =============

BudgetSchema.set('toJSON', {
  virtuals: true,
  transform: function(doc, ret) {
    delete ret.__v;
    return ret;
  },
});

BudgetSchema.set('toObject', { virtuals: true });

// ============= EXPORT =============

module.exports = mongoose.model('Budget', BudgetSchema);

// ============= EXPORT ENUMS =============

module.exports.BUDGET_TYPES = BUDGET_TYPES;
module.exports.BUDGET_PERIODS = BUDGET_PERIODS;
module.exports.INCOME_SOURCES = INCOME_SOURCES;
module.exports.EXPENSE_CATEGORIES = EXPENSE_CATEGORIES;
