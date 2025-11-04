// File: models/Expense.js

const mongoose = require('mongoose');

// ============= ENUMS =============

const EXPENSE_CATEGORIES = {
  // Housing & Utilities
  RENT_MORTGAGE: 'Rent/Mortgage',
  ELECTRICITY: 'Electricity',
  WATER: 'Water',
  GAS: 'Gas',
  INTERNET: 'Internet',
  MAINTENANCE: 'Maintenance',
  PROPERTY_TAX: 'Property Tax',

  // Transportation
  FUEL: 'Fuel',
  VEHICLE_MAINTENANCE: 'Vehicle Maintenance',
  VEHICLE_INSURANCE: 'Vehicle Insurance',
  PARKING: 'Parking',
  PUBLIC_TRANSPORT: 'Public Transport',
  TAXI_RIDE: 'Taxi/Ride',
  VEHICLE_LOAN: 'Vehicle Loan',

  // Food & Dining
  GROCERIES: 'Groceries',
  RESTAURANTS: 'Restaurants',
  SNACKS: 'Snacks',
  COFFEE_BEVERAGES: 'Coffee/Beverages',
  FOOD_DELIVERY: 'Food Delivery',

  // Shopping
  CLOTHING: 'Clothing',
  ACCESSORIES: 'Accessories',
  ELECTRONICS: 'Electronics',
  HOME_DECOR: 'Home Decor',
  ONLINE_SHOPPING: 'Online Shopping',

  // Health & Fitness
  MEDICAL: 'Medical',
  MEDICINES: 'Medicines',
  GYM_FITNESS: 'Gym/Fitness',
  HEALTH_INSURANCE: 'Health Insurance',
  WELLNESS_SPA: 'Wellness/Spa',

  // Education
  SCHOOL_COLLEGE: 'School/College Fees',
  BOOKS: 'Books',
  ONLINE_COURSES: 'Online Courses',
  COACHING: 'Coaching',

  // Bills & Subscriptions
  MOBILE_RECHARGE: 'Mobile Recharge',
  STREAMING_SERVICES: 'Streaming Services',
  SOFTWARE_SUBSCRIPTIONS: 'Software Subscriptions',
  CLOUD_STORAGE: 'Cloud Storage',

  // Work/Business
  OFFICE_RENT: 'Office Rent',
  BUSINESS_SUPPLIES: 'Business Supplies',
  WORK_TRAVEL: 'Work Travel',
  TOOLS_SOFTWARE: 'Tools/Software',
  CONTRACTORS: 'Contractors',

  // Finance
  LOAN_PAYMENTS: 'Loan Payments',
  CREDIT_CARD_BILLS: 'Credit Card Bills',
  INVESTMENTS: 'Investments',
  INSURANCE: 'Insurance',
  SAVINGS: 'Savings',

  // Personal & Family
  CHILD_CARE: 'Child Care',
  ELDER_CARE: 'Elder Care',
  GIFTS: 'Gifts',
  DONATIONS: 'Donations',
  EVENTS: 'Events',

  // Travel & Leisure
  FLIGHTS_TRAINS: 'Flights/Trains',
  HOTELS: 'Hotels',
  TOURS_ACTIVITIES: 'Tours/Activities',
  ENTERTAINMENT: 'Entertainment',

  // Others
  PET_CARE: 'Pet Care',
  EMERGENCY: 'Emergency',
  MISCELLANEOUS: 'Miscellaneous',
};

const CATEGORY_GROUPS = {
  'Housing & Utilities': [
    EXPENSE_CATEGORIES.RENT_MORTGAGE,
    EXPENSE_CATEGORIES.ELECTRICITY,
    EXPENSE_CATEGORIES.WATER,
    EXPENSE_CATEGORIES.GAS,
    EXPENSE_CATEGORIES.INTERNET,
    EXPENSE_CATEGORIES.MAINTENANCE,
    EXPENSE_CATEGORIES.PROPERTY_TAX,
  ],
  'Transportation': [
    EXPENSE_CATEGORIES.FUEL,
    EXPENSE_CATEGORIES.VEHICLE_MAINTENANCE,
    EXPENSE_CATEGORIES.VEHICLE_INSURANCE,
    EXPENSE_CATEGORIES.PARKING,
    EXPENSE_CATEGORIES.PUBLIC_TRANSPORT,
    EXPENSE_CATEGORIES.TAXI_RIDE,
    EXPENSE_CATEGORIES.VEHICLE_LOAN,
  ],
  'Food & Dining': [
    EXPENSE_CATEGORIES.GROCERIES,
    EXPENSE_CATEGORIES.RESTAURANTS,
    EXPENSE_CATEGORIES.SNACKS,
    EXPENSE_CATEGORIES.COFFEE_BEVERAGES,
    EXPENSE_CATEGORIES.FOOD_DELIVERY,
  ],
  'Shopping': [
    EXPENSE_CATEGORIES.CLOTHING,
    EXPENSE_CATEGORIES.ACCESSORIES,
    EXPENSE_CATEGORIES.ELECTRONICS,
    EXPENSE_CATEGORIES.HOME_DECOR,
    EXPENSE_CATEGORIES.ONLINE_SHOPPING,
  ],
  'Health & Fitness': [
    EXPENSE_CATEGORIES.MEDICAL,
    EXPENSE_CATEGORIES.MEDICINES,
    EXPENSE_CATEGORIES.GYM_FITNESS,
    EXPENSE_CATEGORIES.HEALTH_INSURANCE,
    EXPENSE_CATEGORIES.WELLNESS_SPA,
  ],
  'Education': [
    EXPENSE_CATEGORIES.SCHOOL_COLLEGE,
    EXPENSE_CATEGORIES.BOOKS,
    EXPENSE_CATEGORIES.ONLINE_COURSES,
    EXPENSE_CATEGORIES.COACHING,
  ],
  'Bills & Subscriptions': [
    EXPENSE_CATEGORIES.MOBILE_RECHARGE,
    EXPENSE_CATEGORIES.STREAMING_SERVICES,
    EXPENSE_CATEGORIES.SOFTWARE_SUBSCRIPTIONS,
    EXPENSE_CATEGORIES.CLOUD_STORAGE,
  ],
  'Work/Business': [
    EXPENSE_CATEGORIES.OFFICE_RENT,
    EXPENSE_CATEGORIES.BUSINESS_SUPPLIES,
    EXPENSE_CATEGORIES.WORK_TRAVEL,
    EXPENSE_CATEGORIES.TOOLS_SOFTWARE,
    EXPENSE_CATEGORIES.CONTRACTORS,
  ],
  'Finance': [
    EXPENSE_CATEGORIES.LOAN_PAYMENTS,
    EXPENSE_CATEGORIES.CREDIT_CARD_BILLS,
    EXPENSE_CATEGORIES.INVESTMENTS,
    EXPENSE_CATEGORIES.INSURANCE,
    EXPENSE_CATEGORIES.SAVINGS,
  ],
  'Personal & Family': [
    EXPENSE_CATEGORIES.CHILD_CARE,
    EXPENSE_CATEGORIES.ELDER_CARE,
    EXPENSE_CATEGORIES.GIFTS,
    EXPENSE_CATEGORIES.DONATIONS,
    EXPENSE_CATEGORIES.EVENTS,
  ],
  'Travel & Leisure': [
    EXPENSE_CATEGORIES.FLIGHTS_TRAINS,
    EXPENSE_CATEGORIES.HOTELS,
    EXPENSE_CATEGORIES.TOURS_ACTIVITIES,
    EXPENSE_CATEGORIES.ENTERTAINMENT,
  ],
  'Others': [
    EXPENSE_CATEGORIES.PET_CARE,
    EXPENSE_CATEGORIES.EMERGENCY,
    EXPENSE_CATEGORIES.MISCELLANEOUS,
  ],
};

const PAYMENT_METHODS = {
  CASH: 'cash',
  CREDIT_CARD: 'credit_card',
  DEBIT_CARD: 'debit_card',
  UPI: 'upi',
  BANK_TRANSFER: 'bank_transfer',
  WALLET: 'wallet',
  CHEQUE: 'cheque',
  OTHER: 'other',
};

// ============= EXPENSE SCHEMA =============

const ExpenseSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User is required'],
      index: true,
    },

    // Link to Reminder for payment sync
    reminderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Reminder',
      default: null,
      index: true,
    },

    title: {
      type: String,
      required: [true, 'Please provide a title'],
      trim: true,
      maxlength: [100, 'Title cannot exceed 100 characters'],
      minlength: [1, 'Title must have at least 1 character'],
    },

    amount: {
      type: Number,
      required: [true, 'Please provide an amount'],
      min: [0, 'Amount must be non-negative'],
      max: [999999999.99, 'Amount exceeds maximum allowed'],
      validate: {
        validator: function(value) {
          return value > 0;
        },
        message: 'Amount must be greater than 0',
      },
    },

    category: {
      type: String,
      required: [true, 'Please provide a category'],
      enum: {
        values: Object.values(EXPENSE_CATEGORIES),
        message: 'Invalid expense category',
      },
      default: EXPENSE_CATEGORIES.MISCELLANEOUS,
      index: true,
    },

    description: {
      type: String,
      trim: true,
      default: '',
      maxlength: [500, 'Description cannot exceed 500 characters'],
    },

    date: {
      type: Date,
      required: [true, 'Please provide a date'],
      default: Date.now,
      index: true,
    },

    // ============= ADDITIONAL FIELDS =============

    paymentMethod: {
      type: String,
      enum: {
        values: Object.values(PAYMENT_METHODS),
        message: 'Invalid payment method',
      },
      default: PAYMENT_METHODS.CASH,
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

    notes: {
      type: String,
      trim: true,
      maxlength: [1000, 'Notes cannot exceed 1000 characters'],
    },

    receipt: {
      url: String,
      fileName: String,
      uploadedAt: Date,
    },

    attachment: {
      type: String,
      trim: true,
    },

    isRecurring: {
      type: Boolean,
      default: false,
    },

    recurringPattern: {
      frequency: {
        type: String,
        enum: ['daily', 'weekly', 'biweekly', 'monthly', 'quarterly', 'yearly'],
      },
      endDate: Date,
    },

    isBillPayment: {
      type: Boolean,
      default: false,
    },

    isReimbursable: {
      type: Boolean,
      default: false,
    },

    reimbursementStatus: {
      type: String,
      enum: ['pending', 'approved', 'rejected', 'reimbursed'],
      default: 'pending',
    },

    category_group: {
      type: String,
      // Will be computed and set before save
    },

    // Audit fields
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

ExpenseSchema.index({ user: 1, date: -1 });
ExpenseSchema.index({ user: 1, category: 1 });
ExpenseSchema.index({ user: 1, category_group: 1 });
ExpenseSchema.index({ user: 1, paymentMethod: 1 });
ExpenseSchema.index({ reminderId: 1 });
ExpenseSchema.index({ user: 1, createdAt: -1 });
ExpenseSchema.index({ user: 1, isRecurring: 1 });
ExpenseSchema.index({ user: 1, isBillPayment: 1 });
ExpenseSchema.index({ user: 1, deletedAt: 1 });
// Compound indexes for common queries
ExpenseSchema.index({ user: 1, date: -1, category: 1 });
ExpenseSchema.index({ user: 1, date: -1, paymentMethod: 1 });

// ============= VIRTUAL FIELDS =============

/**
 * Get formatted amount
 */
ExpenseSchema.virtual('formattedAmount').get(function() {
  return `₹${this.amount.toFixed(2)}`;
});

/**
 * Get formatted date
 */
ExpenseSchema.virtual('formattedDate').get(function() {
  return new Date(this.date).toLocaleDateString('en-IN', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
});

/**
 * Get time since creation
 */
ExpenseSchema.virtual('timeSince').get(function() {
  const now = new Date();
  const diff = now - this.createdAt;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`;
  if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  return 'Just now';
});

/**
 * Check if expense is recent (within 7 days)
 */
ExpenseSchema.virtual('isRecent').get(function() {
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  return this.createdAt > sevenDaysAgo;
});

/**
 * Check if expense is deleted
 */
ExpenseSchema.virtual('isDeleted').get(function() {
  return this.deletedAt !== null;
});

// ============= INSTANCE METHODS =============

/**
 * Get expense summary
 */
ExpenseSchema.methods.getSummary = function() {
  return {
    id: this._id,
    title: this.title,
    amount: this.amount,
    formattedAmount: this.formattedAmount,
    category: this.category,
    category_group: this.category_group,
    date: this.date,
    formattedDate: this.formattedDate,
    paymentMethod: this.paymentMethod,
    vendor: this.vendor,
    description: this.description,
    tags: this.tags,
    isRecurring: this.isRecurring,
    isBillPayment: this.isBillPayment,
    isReimbursable: this.isReimbursable,
    reimbursementStatus: this.reimbursementStatus,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
};

/**
 * Mark as reimbursable
 */
ExpenseSchema.methods.markForReimbursement = function() {
  this.isReimbursable = true;
  this.reimbursementStatus = 'pending';
  return this.save();
};

/**
 * Update reimbursement status
 */
ExpenseSchema.methods.updateReimbursementStatus = function(status, userId) {
  if (!['pending', 'approved', 'rejected', 'reimbursed'].includes(status)) {
    throw new Error('Invalid reimbursement status');
  }
  this.reimbursementStatus = status;
  this.updatedBy = userId;
  return this.save();
};

/**
 * Soft delete expense
 */
ExpenseSchema.methods.softDelete = function(userId) {
  this.deletedAt = new Date();
  this.deletedBy = userId;
  return this.save();
};

/**
 * Restore deleted expense
 */
ExpenseSchema.methods.restore = function(userId) {
  this.deletedAt = null;
  this.deletedBy = null;
  this.updatedBy = userId;
  return this.save();
};

/**
 * Link to reminder
 */
ExpenseSchema.methods.linkToReminder = function(reminderId) {
  this.reminderId = reminderId;
  return this.save();
};

/**
 * Update expense
 */
ExpenseSchema.methods.updateExpense = function(updates, userId) {
  const allowedFields = [
    'title',
    'amount',
    'category',
    'description',
    'date',
    'paymentMethod',
    'vendor',
    'tags',
    'notes',
    'isRecurring',
    'isBillPayment',
  ];

  for (const [key, value] of Object.entries(updates)) {
    if (allowedFields.includes(key)) {
      this[key] = value;
    }
  }

  this.updatedBy = userId;
  return this.save();
};

// ============= STATIC METHODS =============

/**
 * Get expenses for user with filters
 */
ExpenseSchema.statics.getExpensesWithFilters = async function(
  userId,
  { startDate, endDate, category, paymentMethod, vendor, tags, isRecurring, isBillPayment, limit = 20, skip = 0 }
) {
  const query = { user: userId, deletedAt: null };

  if (startDate || endDate) {
    query.date = {};
    if (startDate) query.date.$gte = new Date(startDate);
    if (endDate) {
      const end = new Date(endDate);
      end.setHours(23, 59, 59, 999);
      query.date.$lte = end;
    }
  }

  if (category) query.category = category;
  if (paymentMethod) query.paymentMethod = paymentMethod;
  if (vendor) query.vendor = new RegExp(vendor, 'i');
  if (tags && tags.length > 0) query.tags = { $in: tags };
  if (isRecurring !== undefined) query.isRecurring = isRecurring;
  if (isBillPayment !== undefined) query.isBillPayment = isBillPayment;

  const total = await this.countDocuments(query);
  const expenses = await this.find(query).sort({ date: -1 }).skip(skip).limit(limit).lean();

  return { expenses, total, pages: Math.ceil(total / limit) };
};

/**
 * Get total spent in date range
 */
ExpenseSchema.statics.getTotalSpent = async function(userId, startDate, endDate) {
  const query = { user: userId, deletedAt: null };

  if (startDate && endDate) {
    query.date = {
      $gte: new Date(startDate),
      $lte: new Date(endDate),
    };
  }

  const result = await this.aggregate([
    { $match: query },
    { $group: { _id: null, total: { $sum: '$amount' } } },
  ]);

  return result.length > 0 ? result[0].total : 0;
};

/**
 * Get expenses by category
 */
ExpenseSchema.statics.getByCategory = async function(userId, category, { startDate, endDate } = {}) {
  const query = { user: userId, category, deletedAt: null };

  if (startDate && endDate) {
    query.date = {
      $gte: new Date(startDate),
      $lte: new Date(endDate),
    };
  }

  return this.find(query).sort({ date: -1 });
};

/**
 * Get expenses by category group
 */
ExpenseSchema.statics.getByGroup = async function(userId, group, { startDate, endDate } = {}) {
  const query = { user: userId, category_group: group, deletedAt: null };

  if (startDate && endDate) {
    query.date = {
      $gte: new Date(startDate),
      $lte: new Date(endDate),
    };
  }

  return this.find(query).sort({ date: -1 });
};

/**
 * Get category breakdown
 */
ExpenseSchema.statics.getCategoryBreakdown = async function(userId, { startDate, endDate } = {}) {
  const query = { user: userId, deletedAt: null };

  if (startDate && endDate) {
    query.date = {
      $gte: new Date(startDate),
      $lte: new Date(endDate),
    };
  }

  return this.aggregate([
    { $match: query },
    {
      $group: {
        _id: '$category',
        total: { $sum: '$amount' },
        count: { $sum: 1 },
        average: { $avg: '$amount' },
      },
    },
    {
      $project: {
        _id: 0,
        category: '$_id',
        total: { $round: ['$total', 2] },
        count: 1,
        average: { $round: ['$average', 2] },
      },
    },
    { $sort: { total: -1 } },
  ]);
};

/**
 * Get group breakdown
 */
ExpenseSchema.statics.getGroupBreakdown = async function(userId, { startDate, endDate } = {}) {
  const query = { user: userId, deletedAt: null };

  if (startDate && endDate) {
    query.date = {
      $gte: new Date(startDate),
      $lte: new Date(endDate),
    };
  }

  return this.aggregate([
    { $match: query },
    {
      $group: {
        _id: '$category_group',
        total: { $sum: '$amount' },
        count: { $sum: 1 },
      },
    },
    {
      $project: {
        _id: 0,
        group: '$_id',
        total: { $round: ['$total', 2] },
        count: 1,
      },
    },
    { $sort: { total: -1 } },
  ]);
};

/**
 * Get payment method breakdown
 */
ExpenseSchema.statics.getPaymentMethodBreakdown = async function(userId, { startDate, endDate } = {}) {
  const query = { user: userId, deletedAt: null };

  if (startDate && endDate) {
    query.date = {
      $gte: new Date(startDate),
      $lte: new Date(endDate),
    };
  }

  return this.aggregate([
    { $match: query },
    {
      $group: {
        _id: '$paymentMethod',
        total: { $sum: '$amount' },
        count: { $sum: 1 },
      },
    },
    {
      $project: {
        _id: 0,
        method: '$_id',
        total: { $round: ['$total', 2] },
        count: 1,
      },
    },
    { $sort: { total: -1 } },
  ]);
};

/**
 * Get monthly breakdown
 */
ExpenseSchema.statics.getMonthlyBreakdown = async function(userId, year = null) {
  const currentYear = year || new Date().getFullYear();
  const query = {
    user: userId,
    deletedAt: null,
    date: {
      $gte: new Date(`${currentYear}-01-01`),
      $lt: new Date(`${currentYear + 1}-01-01`),
    },
  };

  return this.aggregate([
    { $match: query },
    {
      $group: {
        _id: { $month: '$date' },
        total: { $sum: '$amount' },
        count: { $sum: 1 },
        average: { $avg: '$amount' },
      },
    },
    {
      $project: {
        _id: 0,
        month: '$_id',
        total: { $round: ['$total', 2] },
        count: 1,
        average: { $round: ['$average', 2] },
      },
    },
    { $sort: { month: 1 } },
  ]);
};

/**
 * Get reimbursable expenses
 */
ExpenseSchema.statics.getReimbursable = async function(userId, status = 'pending') {
  return this.find({
    user: userId,
    isReimbursable: true,
    reimbursementStatus: status,
    deletedAt: null,
  }).sort({ date: -1 });
};

/**
 * Get recurring expenses
 */
ExpenseSchema.statics.getRecurring = async function(userId) {
  return this.find({
    user: userId,
    isRecurring: true,
    deletedAt: null,
  }).sort({ date: -1 });
};

/**
 * Get bill payments
 */
ExpenseSchema.statics.getBillPayments = async function(userId) {
  return this.find({
    user: userId,
    isBillPayment: true,
    deletedAt: null,
  }).sort({ date: -1 });
};

/**
 * Get average daily spending
 */
ExpenseSchema.statics.getAverageDailySpending = async function(userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  const total = await this.getTotalSpent(userId, startDate, new Date());
  return parseFloat((total / days).toFixed(2));
};

/**
 * Get high spending alerts (expenses above threshold)
 */
ExpenseSchema.statics.getHighSpendingAlerts = async function(userId, threshold) {
  return this.find({
    user: userId,
    amount: { $gte: threshold },
    deletedAt: null,
  })
    .sort({ amount: -1, date: -1 })
    .limit(10);
};

/**
 * Get spending trend
 */
ExpenseSchema.statics.getSpendingTrend = async function(userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return this.aggregate([
    {
      $match: {
        user: mongoose.Types.ObjectId(userId),
        deletedAt: null,
        date: { $gte: startDate },
      },
    },
    {
      $group: {
        _id: { $dateToString: { format: '%Y-%m-%d', date: '$date' } },
        total: { $sum: '$amount' },
        count: { $sum: 1 },
      },
    },
    { $sort: { _id: 1 } },
  ]);
};

/**
 * Search expenses
 */
ExpenseSchema.statics.searchExpenses = async function(userId, searchTerm, { limit = 20, skip = 0 } = {}) {
  const regex = new RegExp(searchTerm, 'i');
  const query = {
    user: userId,
    deletedAt: null,
    $or: [
      { title: regex },
      { description: regex },
      { vendor: regex },
      { tags: { $in: [regex] } },
    ],
  };

  const total = await this.countDocuments(query);
  const results = await this.find(query)
    .sort({ date: -1 })
    .skip(skip)
    .limit(limit)
    .lean();

  return { results, total };
};

// ============= MIDDLEWARE =============

/**
 * Pre-save: Set category group and validate
 */
ExpenseSchema.pre('save', function(next) {
  // Set category group
  for (const [group, categories] of Object.entries(CATEGORY_GROUPS)) {
    if (categories.includes(this.category)) {
      this.category_group = group;
      break;
    }
  }

  // Ensure amount is positive
  if (this.amount <= 0) {
    throw new Error('Amount must be greater than 0');
  }

  next();
});

/**
 * Post-save logging
 */
ExpenseSchema.post('save', function(doc) {
  console.log(`Expense ${doc._id} saved successfully`);
});

// ============= JSON OUTPUT OPTIONS =============

ExpenseSchema.set('toJSON', {
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

ExpenseSchema.set('toObject', { virtuals: true });

// ============= EXPORT =============

module.exports = mongoose.model('Expense', ExpenseSchema);

// ============= EXPORT ENUMS & CONSTANTS =============

module.exports.EXPENSE_CATEGORIES = EXPENSE_CATEGORIES;
module.exports.CATEGORY_GROUPS = CATEGORY_GROUPS;
module.exports.PAYMENT_METHODS = PAYMENT_METHODS;
