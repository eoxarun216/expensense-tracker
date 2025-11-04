const mongoose = require('mongoose');

const BudgetSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true, // Index for faster queries by user
  },
  category: {
    type: String,
    required: true,
    trim: true,
  },
  type: {
    type: String,
    enum: ['expense', 'income'],
    default: 'expense',
    required: true,
  },
  limit: {
    type: Number,
    required: true,
    min: 0,
    default: 0,
  },
  spent: {
    type: Number,
    default: 0.0,
    min: 0,
  },
  period: {
    type: String,
    enum: ['weekly', 'monthly', 'yearly'],
    default: 'monthly',
  },
  // ============= INCOME-SPECIFIC FIELDS =============
  incomeSource: {
    type: String,
    enum: ['personal', 'family', 'business', 'investment', 'other', 'additional'], // Added 'additional' enum value if needed by your frontend
    trim: true,
    // Only required if type is 'income'
    required: function() {
      return this.type === 'income';
    },
  },
  incomeAmount: {
    type: Number,
    min: 0,
    // Only required if type is 'income'
    required: function() {
      return this.type === 'income';
    },
    // Validate that incomeAmount is set for income entries
    validate: {
      validator: function(value) {
        if (this.type === 'income') {
          return value !== null && value !== undefined && value >= 0;
        }
        return true;
      },
      message: 'Income amount is required for income entries',
    },
  },
  // createdAt and updatedAt are handled by timestamps: true
}, {
  timestamps: true, // Automatically manages createdAt and updatedAt
});

// ============= INDEXES FOR PERFORMANCE =============

// Compound index for common queries
BudgetSchema.index({ userId: 1, type: 1, period: 1 });
BudgetSchema.index({ userId: 1, category: 1 });
BudgetSchema.index({ userId: 1, incomeSource: 1 });

// ============= VIRTUAL FIELDS =============

// Virtual for checking if this is an income entry
BudgetSchema.virtual('isIncome').get(function() {
  return this.type === 'income';
});

// Virtual for checking if this is an expense entry
BudgetSchema.virtual('isExpense').get(function() {
  return this.type === 'expense';
});

// Virtual for getting effective amount
BudgetSchema.virtual('effectiveAmount').get(function() {
  return this.type === 'income' ? this.incomeAmount : this.spent;
});

// Virtual for budget usage percentage (for expenses)
BudgetSchema.virtual('usagePercentage').get(function() {
  if (this.type === 'expense' && this.limit > 0) {
    return (this.spent / this.limit) * 100;
  }
  return 0;
});

// Virtual for remaining budget (for expenses)
BudgetSchema.virtual('remaining').get(function() {
  if (this.type === 'expense') {
    const rem = this.limit - this.spent;
    return rem > 0 ? rem : 0;
  }
  return 0;
});

// Virtual for budget status (for expenses)
BudgetSchema.virtual('status').get(function() {
  if (this.type === 'income') return 'income';
  
  if (this.spent > this.limit) return 'exceeded';
  if (this.spent >= this.limit * 0.8) return 'warning';
  return 'safe';
});

// ============= INSTANCE METHODS =============

// Method to update spent amount (for expenses)
BudgetSchema.methods.updateSpent = function(amount) {
  if (this.type === 'expense') {
    this.spent = amount;
    // updatedAt will be updated automatically by timestamps
    return this.save();
  }
  throw new Error('Cannot update spent amount for income entries');
};

// Method to update income amount
BudgetSchema.methods.updateIncome = function(amount) {
  if (this.type === 'income') {
    this.incomeAmount = amount;
    // updatedAt will be updated automatically by timestamps
    return this.save();
  }
  throw new Error('Cannot update income amount for expense entries');
};

// ============= STATIC METHODS =============

// Get all income entries for a user
BudgetSchema.statics.getIncomeByUser = function(userId) {
  return this.find({ userId, type: 'income' }).sort({ createdAt: -1 });
};

// Get all expense entries (budgets) for a user
BudgetSchema.statics.getExpensesByUser = function(userId) {
  return this.find({ userId, type: 'expense' }).sort({ createdAt: -1 });
};

// Get income by source for a user
BudgetSchema.statics.getIncomeBySource = function(userId, source) {
  return this.find({ userId, type: 'income', incomeSource: source });
};

// Calculate total income for a user
BudgetSchema.statics.getTotalIncome = async function(userId, period = null) {
  const query = { userId, type: 'income' };
  if (period) query.period = period;
  
  const result = await this.aggregate([
    { $match: query },
    {
      $group: {
        _id: null,
        total: { $sum: '$incomeAmount' },
      },
    },
  ]);
  
  return result.length > 0 ? result[0].total : 0;
};

// Calculate total expenses for a user
BudgetSchema.statics.getTotalExpenses = async function(userId, period = null) {
  const query = { userId, type: 'expense' };
  if (period) query.period = period;
  
  const result = await this.aggregate([
    { $match: query },
    {
      $group: {
        _id: null,
        total: { $sum: '$spent' },
      },
    },
  ]);
  
  return result.length > 0 ? result[0].total : 0;
};

// Calculate net income (income - expenses) for a user
BudgetSchema.statics.getNetIncome = async function(userId, period = null) {
  const totalIncome = await this.getTotalIncome(userId, period);
  const totalExpenses = await this.getTotalExpenses(userId, period);
  return totalIncome - totalExpenses;
};

// Get income breakdown by source
BudgetSchema.statics.getIncomeBreakdown = async function(userId, period = null) {
  const query = { userId, type: 'income' };
  if (period) query.period = period;
  
  return this.aggregate([
    { $match: query },
    {
      $group: {
        _id: '$incomeSource',
        total: { $sum: '$incomeAmount' },
        count: { $sum: 1 },
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
  ]);
};

// Get expense breakdown by category
BudgetSchema.statics.getExpenseBreakdown = async function(userId, period = null) {
  const query = { userId, type: 'expense' };
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
        usagePercentage: {
          $multiply: [
            { $divide: ['$totalSpent', '$totalLimit'] },
            100,
          ],
        },
      },
    },
  ]);
};

// Get financial health score
BudgetSchema.statics.getFinancialHealth = async function(userId, period = null) {
  const totalIncome = await this.getTotalIncome(userId, period);
  const totalExpenses = await this.getTotalExpenses(userId, period);
  
  if (totalIncome === 0) return { score: 0, status: 'no_income' };
  
  const expenseRatio = totalExpenses / totalIncome;
  
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
    savingsRate: ((totalIncome - totalExpenses) / totalIncome) * 100,
  };
};

// ============= MIDDLEWARE =============

// Pre-save validation and data integrity
BudgetSchema.pre('save', function(next) {
  // Ensure income entries don't have spent values
  if (this.type === 'income') {
    this.spent = 0;
    if (this.limit > 0) this.limit = 0; // Or perhaps throw an error if limit is set for income?
  }
  
  // Ensure expense entries don't have income fields
  if (this.type === 'expense') {
    this.incomeAmount = undefined;
    if (!this.incomeSource) this.incomeSource = undefined;
  }
  
  // updatedAt is handled automatically by timestamps: true
  next();
});

// ============= OPTIONS =============

// Include virtuals in JSON output
BudgetSchema.set('toJSON', {
  virtuals: true,
  transform: function(doc, ret) {
    delete ret.__v;
    return ret;
  },
});

BudgetSchema.set('toObject', { virtuals: true });

module.exports = mongoose.model('Budget', BudgetSchema);