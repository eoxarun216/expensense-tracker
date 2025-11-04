// File: routes/budgetRoutes.js

const express = require('express');
const router = express.Router();
const { body, query, validationResult } = require('express-validator');
const logger = require('../utils/logger');

const Budget = require('../models/Budget');
const { protect, authorize } = require('../middleware/auth');
const rateLimiter = require('../middleware/rateLimiter');
const validateRequest = require('../middleware/validateRequest');

// ============= VALIDATION SCHEMAS =============

const createBudgetValidation = [
  body('category')
    .trim()
    .notEmpty()
    .withMessage('Category is required'),
  body('type')
    .optional()
    .isIn(['expense', 'income'])
    .withMessage('Type must be either "expense" or "income"'),
  body('period')
    .optional()
    .isIn(['weekly', 'monthly', 'yearly'])
    .withMessage('Period must be weekly, monthly, or yearly'),
  body('limit')
    .if((value, { req }) => req.body.type !== 'income')
    .notEmpty()
    .withMessage('Limit is required for expense budgets')
    .isFloat({ min: 0, max: 999999999.99 })
    .withMessage('Limit must be a valid amount'),
  body('incomeSource')
    .if((value, { req }) => req.body.type === 'income')
    .notEmpty()
    .withMessage('Income source is required for income entries')
    .isIn(['personal', 'family', 'business', 'investment', 'additional', 'other'])
    .withMessage('Invalid income source'),
  body('incomeAmount')
    .if((value, { req }) => req.body.type === 'income')
    .notEmpty()
    .withMessage('Income amount is required')
    .isFloat({ min: 0.01, max: 999999999.99 })
    .withMessage('Income amount must be between 0.01 and 999,999,999.99'),
  body('spent')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Spent must be a valid amount'),
  body('alertThreshold')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Alert threshold must be between 0 and 100'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters'),
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Notes cannot exceed 1000 characters'),
];

const updateBudgetValidation = [
  body('category')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Category cannot be empty'),
  body('limit')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Limit must be a valid amount'),
  body('spent')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Spent must be a valid amount'),
  body('period')
    .optional()
    .isIn(['weekly', 'monthly', 'yearly'])
    .withMessage('Period must be weekly, monthly, or yearly'),
  body('alertThreshold')
    .optional()
    .isInt({ min: 0, max: 100 })
    .withMessage('Alert threshold must be between 0 and 100'),
];

const incomeValidation = [
  body('amount')
    .notEmpty()
    .withMessage('Amount is required')
    .isFloat({ min: 0.01 })
    .withMessage('Amount must be greater than 0'),
  body('period')
    .optional()
    .isIn(['weekly', 'monthly', 'yearly'])
    .withMessage('Period must be weekly, monthly, or yearly'),
];

const spentValidation = [
  body('spent')
    .notEmpty()
    .withMessage('Spent amount is required')
    .isFloat({ min: 0 })
    .withMessage('Spent must be a valid amount'),
];

const filterValidation = [
  query('type')
    .optional()
    .isIn(['expense', 'income'])
    .withMessage('Type must be expense or income'),
  query('period')
    .optional()
    .isIn(['weekly', 'monthly', 'yearly'])
    .withMessage('Invalid period'),
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
];

// ============= HELPER FUNCTIONS =============

const buildBudgetQuery = (userId, filters = {}) => {
  const query = { userId, active: true };

  if (filters.type) query.type = filters.type;
  if (filters.period) query.period = filters.period;
  if (filters.category) query.category = filters.category;
  if (filters.incomeSource) query.incomeSource = filters.incomeSource;

  return query;
};

const getPagination = (page = 1, limit = 20) => {
  const pageNum = Math.max(1, parseInt(page));
  const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
  return {
    skip: (pageNum - 1) * limitNum,
    limit: limitNum,
    page: pageNum,
  };
};

// ============= GET ROUTES =============

/**
 * @route   GET /api/budgets
 * @desc    Get all budgets (income + expenses) with filters
 * @access  Private
 */
router.get(
  '/',
  protect,
  rateLimiter.general,
  filterValidation,
  validateRequest,
  async (req, res) => {
    try {
      logger.info('GetBudgets: Request received', { userId: req.user._id });

      const { type, period, category, incomeSource, page = 1, limit = 20, sortBy = 'createdAt' } = req.query;

      const { skip, limitNum, page: pageNum } = getPagination(page, limit);

      // Build query
      const query = buildBudgetQuery(req.user._id, {
        type,
        period,
        category,
        incomeSource,
      });

      // Build sort
      const sortOptions = {};
      switch (sortBy) {
        case 'amount':
          sortOptions.limit = -1;
          break;
        case 'spent':
          sortOptions.spent = -1;
          break;
        case 'name':
          sortOptions.category = 1;
          break;
        default:
          sortOptions.createdAt = -1;
      }

      // Execute queries
      const budgets = await Budget.find(query)
        .sort(sortOptions)
        .skip(skip)
        .limit(limitNum)
        .lean();

      const total = await Budget.countDocuments(query);

      logger.info('GetBudgets: Retrieved successfully', {
        userId: req.user._id,
        count: budgets.length,
        total,
      });

      res.json({
        success: true,
        data: {
          budgets,
          pagination: {
            page: pageNum,
            limit: limitNum,
            total,
            pages: Math.ceil(total / limitNum),
          },
        },
      });
    } catch (error) {
      logger.error('GetBudgets error', { error: error.message, userId: req.user._id });
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve budgets',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }
);

/**
 * @route   GET /api/budgets/:id
 * @desc    Get single budget
 * @access  Private
 */
router.get('/:id', protect, rateLimiter.general, async (req, res) => {
  try {
    const budget = await Budget.findById(req.params.id);

    if (!budget) {
      logger.warn('GetBudget: Budget not found', { budgetId: req.params.id });
      return res.status(404).json({
        success: false,
        message: 'Budget not found',
      });
    }

    // Check authorization
    if (budget.userId.toString() !== req.user._id.toString()) {
      logger.warn('GetBudget: Unauthorized access', {
        budgetId: req.params.id,
        userId: req.user._id,
      });
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this budget',
      });
    }

    logger.info('GetBudget: Retrieved successfully', { budgetId: budget._id });

    res.json({
      success: true,
      budget: budget.getSummary(),
    });
  } catch (error) {
    logger.error('GetBudget error', { error: error.message, budgetId: req.params.id });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve budget',
    });
  }
});

/**
 * @route   GET /api/budgets/summary/all
 * @desc    Get financial summary (income, expenses, health)
 * @access  Private
 */
router.get('/summary/all', protect, rateLimiter.general, async (req, res) => {
  try {
    const { period } = req.query;

    logger.info('GetSummary: Request received', { userId: req.user._id });

    const [
      totalIncome,
      totalExpenses,
      totalLimit,
      incomeBreakdown,
      expenseBreakdown,
      financialHealth,
    ] = await Promise.all([
      Budget.getTotalIncome(req.user._id, period),
      Budget.getTotalExpenses(req.user._id, period),
      Budget.getTotalBudgetLimit(req.user._id, period),
      Budget.getIncomeBreakdown(req.user._id, period),
      Budget.getExpenseBreakdown(req.user._id, period),
      Budget.getFinancialHealth(req.user._id, period),
    ]);

    logger.info('GetSummary: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      summary: {
        totalIncome: parseFloat(totalIncome.toFixed(2)),
        totalExpenses: parseFloat(totalExpenses.toFixed(2)),
        totalBudgetLimit: parseFloat(totalLimit.toFixed(2)),
        netIncome: parseFloat((totalIncome - totalExpenses).toFixed(2)),
        remaining: parseFloat((totalLimit - totalExpenses).toFixed(2)),
        savingsRate: totalIncome > 0
          ? parseFloat(
              (((totalIncome - totalExpenses) / totalIncome) * 100).toFixed(2)
            )
          : 0,
        incomeBreakdown,
        expenseBreakdown,
        financialHealth,
      },
    });
  } catch (error) {
    logger.error('GetSummary error', { error: error.message, userId: req.user._id });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve summary',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
});

/**
 * @route   GET /api/budgets/income/all
 * @desc    Get all income entries
 * @access  Private
 */
router.get('/income/all', protect, rateLimiter.general, async (req, res) => {
  try {
    const { period, page = 1, limit = 20 } = req.query;

    logger.info('GetIncome: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const query = buildBudgetQuery(req.user._id, { type: 'income', period });

    const incomes = await Budget.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Budget.countDocuments(query);

    logger.info('GetIncome: Retrieved successfully', {
      userId: req.user._id,
      count: incomes.length,
    });

    res.json({
      success: true,
      data: {
        incomes,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('GetIncome error', { error: error.message, userId: req.user._id });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve income entries',
    });
  }
});

/**
 * @route   GET /api/budgets/expenses/all
 * @desc    Get all expense budgets
 * @access  Private
 */
router.get('/expenses/all', protect, rateLimiter.general, async (req, res) => {
  try {
    const { period, page = 1, limit = 20 } = req.query;

    logger.info('GetExpenses: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const query = buildBudgetQuery(req.user._id, { type: 'expense', period });

    const expenses = await Budget.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Budget.countDocuments(query);

    logger.info('GetExpenses: Retrieved successfully', {
      userId: req.user._id,
      count: expenses.length,
    });

    res.json({
      success: true,
      data: {
        expenses,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('GetExpenses error', { error: error.message, userId: req.user._id });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve expenses',
    });
  }
});

// ============= ANALYTICS ROUTES =============

/**
 * @route   GET /api/budgets/analytics/income-breakdown
 * @desc    Get income breakdown by source
 * @access  Private
 */
router.get('/analytics/income-breakdown', protect, rateLimiter.general, async (req, res) => {
  try {
    const { period } = req.query;

    logger.info('GetIncomeBreakdown: Request received', { userId: req.user._id });

    const breakdown = await Budget.getIncomeBreakdown(req.user._id, period);

    logger.info('GetIncomeBreakdown: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      breakdown,
    });
  } catch (error) {
    logger.error('GetIncomeBreakdown error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve income breakdown',
    });
  }
});

/**
 * @route   GET /api/budgets/analytics/expense-breakdown
 * @desc    Get expense breakdown by category
 * @access  Private
 */
router.get('/analytics/expense-breakdown', protect, rateLimiter.general, async (req, res) => {
  try {
    const { period } = req.query;

    logger.info('GetExpenseBreakdown: Request received', { userId: req.user._id });

    const breakdown = await Budget.getExpenseBreakdown(req.user._id, period);

    logger.info('GetExpenseBreakdown: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      breakdown,
    });
  } catch (error) {
    logger.error('GetExpenseBreakdown error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve expense breakdown',
    });
  }
});

/**
 * @route   GET /api/budgets/analytics/health
 * @desc    Get financial health score
 * @access  Private
 */
router.get('/analytics/health', protect, rateLimiter.general, async (req, res) => {
  try {
    const { period } = req.query;

    logger.info('GetHealth: Request received', { userId: req.user._id });

    const health = await Budget.getFinancialHealth(req.user._id, period);

    logger.info('GetHealth: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      health,
    });
  } catch (error) {
    logger.error('GetHealth error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve financial health',
    });
  }
});

/**
 * @route   GET /api/budgets/analytics/category-summary
 * @desc    Get category summary
 * @access  Private
 */
router.get('/analytics/category-summary', protect, rateLimiter.general, async (req, res) => {
  try {
    logger.info('GetCategorySummary: Request received', { userId: req.user._id });

    const summary = await Budget.getCategorySummary(req.user._id);

    logger.info('GetCategorySummary: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      summary,
    });
  } catch (error) {
    logger.error('GetCategorySummary error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve category summary',
    });
  }
});

/**
 * @route   GET /api/budgets/analytics/warnings
 * @desc    Get budgets with warnings
 * @access  Private
 */
router.get('/analytics/warnings', protect, rateLimiter.general, async (req, res) => {
  try {
    const { period } = req.query;

    logger.info('GetWarnings: Request received', { userId: req.user._id });

    const warnings = await Budget.getWarningBudgets(req.user._id, period);

    logger.info('GetWarnings: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      warnings,
    });
  } catch (error) {
    logger.error('GetWarnings error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve warnings',
    });
  }
});

/**
 * @route   GET /api/budgets/analytics/exceeded
 * @desc    Get exceeded budgets
 * @access  Private
 */
router.get('/analytics/exceeded', protect, rateLimiter.general, async (req, res) => {
  try {
    logger.info('GetExceeded: Request received', { userId: req.user._id });

    const exceeded = await Budget.getExceededBudgets(req.user._id);

    logger.info('GetExceeded: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      exceeded,
    });
  } catch (error) {
    logger.error('GetExceeded error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve exceeded budgets',
    });
  }
});

// ============= CREATE ROUTES =============

/**
 * @route   POST /api/budgets
 * @desc    Create budget (expense) or income
 * @access  Private
 */
router.post(
  '/',
  protect,
  rateLimiter.general,
  createBudgetValidation,
  validateRequest,
  async (req, res) => {
    try {
      const {
        category,
        limit,
        period,
        type,
        incomeSource,
        incomeAmount,
        description,
        notes,
        alertThreshold,
        notifyOnExceed,
      } = req.body;

      logger.info('CreateBudget: Request received', { userId: req.user._id, type });

      // Check if entry already exists
      const query = {
        userId: req.user._id,
        category,
        period: period || 'monthly',
        type: type || 'expense',
        active: true,
      };

      if (type === 'income') {
        query.incomeSource = incomeSource;
      }

      const existingEntry = await Budget.findOne(query);

      if (existingEntry) {
        logger.warn('CreateBudget: Entry already exists', { userId: req.user._id });
        return res.status(409).json({
          success: false,
          message: `${type === 'income' ? 'Income' : 'Budget'} already exists for this category and period`,
        });
      }

      // Create budget
      const budgetData = {
        userId: req.user._id,
        category,
        period: period || 'monthly',
        type: type || 'expense',
        description,
        notes,
        alertThreshold: alertThreshold || 80,
        notifyOnExceed: notifyOnExceed !== false,
      };

      if (type === 'income') {
        budgetData.incomeSource = incomeSource;
        budgetData.incomeAmount = incomeAmount;
        budgetData.limit = 0;
        budgetData.spent = 0;
      } else {
        budgetData.limit = limit;
        budgetData.spent = 0;
      }

      const budget = await Budget.create(budgetData);

      logger.info('CreateBudget: Created successfully', { budgetId: budget._id });

      res.status(201).json({
        success: true,
        message: `${type === 'income' ? 'Income' : 'Budget'} created successfully`,
        budget: budget.getSummary(),
      });
    } catch (error) {
      logger.error('CreateBudget error', { error: error.message, userId: req.user._id });
      res.status(500).json({
        success: false,
        message: 'Failed to create budget',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }
);

/**
 * @route   POST /api/budgets/income/personal
 * @desc    Set/Update personal income (convenience endpoint)
 * @access  Private
 */
router.post(
  '/income/personal',
  protect,
  rateLimiter.general,
  incomeValidation,
  validateRequest,
  async (req, res) => {
    try {
      const { amount, period } = req.body;

      logger.info('SetPersonalIncome: Request received', { userId: req.user._id });

      // Check if exists
      let income = await Budget.findOne({
        userId: req.user._id,
        type: 'income',
        incomeSource: 'personal',
        period: period || 'monthly',
        active: true,
      });

      if (income) {
        // Update
        await income.updateIncome(amount, req.user._id);
      } else {
        // Create
        income = await Budget.create({
          userId: req.user._id,
          category: 'Personal Income',
          type: 'income',
          incomeSource: 'personal',
          incomeAmount: amount,
          period: period || 'monthly',
          limit: 0,
          spent: 0,
          createdBy: req.user._id,
        });
      }

      logger.info('SetPersonalIncome: Saved successfully', { budgetId: income._id });

      res.json({
        success: true,
        message: 'Personal income set successfully',
        budget: income.getSummary(),
      });
    } catch (error) {
      logger.error('SetPersonalIncome error', { error: error.message });
      res.status(500).json({
        success: false,
        message: 'Failed to set personal income',
      });
    }
  }
);

/**
 * @route   POST /api/budgets/income/family
 * @desc    Set/Update family income
 * @access  Private
 */
router.post(
  '/income/family',
  protect,
  rateLimiter.general,
  incomeValidation,
  validateRequest,
  async (req, res) => {
    try {
      const { amount, period } = req.body;

      logger.info('SetFamilyIncome: Request received', { userId: req.user._id });

      let income = await Budget.findOne({
        userId: req.user._id,
        type: 'income',
        incomeSource: 'family',
        period: period || 'monthly',
        active: true,
      });

      if (income) {
        await income.updateIncome(amount, req.user._id);
      } else {
        income = await Budget.create({
          userId: req.user._id,
          category: 'Family Income',
          type: 'income',
          incomeSource: 'family',
          incomeAmount: amount,
          period: period || 'monthly',
          limit: 0,
          spent: 0,
          createdBy: req.user._id,
        });
      }

      logger.info('SetFamilyIncome: Saved successfully', { budgetId: income._id });

      res.json({
        success: true,
        message: 'Family income set successfully',
        budget: income.getSummary(),
      });
    } catch (error) {
      logger.error('SetFamilyIncome error', { error: error.message });
      res.status(500).json({
        success: false,
        message: 'Failed to set family income',
      });
    }
  }
);

// ============= UPDATE ROUTES =============

/**
 * @route   PUT /api/budgets/:id
 * @desc    Update budget
 * @access  Private
 */
router.put(
  '/:id',
  protect,
  rateLimiter.general,
  updateBudgetValidation,
  validateRequest,
  async (req, res) => {
    try {
      let budget = await Budget.findById(req.params.id);

      if (!budget) {
        logger.warn('UpdateBudget: Budget not found', { budgetId: req.params.id });
        return res.status(404).json({
          success: false,
          message: 'Budget not found',
        });
      }

      // Check authorization
      if (budget.userId.toString() !== req.user._id.toString()) {
        logger.warn('UpdateBudget: Unauthorized', { budgetId: req.params.id });
        return res.status(403).json({
          success: false,
          message: 'Not authorized to update this budget',
        });
      }

      logger.info('UpdateBudget: Update attempt', { budgetId: budget._id });

      // Update allowed fields
      const updates = {};
      const allowedFields = ['category', 'limit', 'spent', 'period', 'alertThreshold', 'description', 'notes', 'incomeAmount', 'notifyOnExceed'];

      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      updates.updatedBy = req.user._id;

      budget = await Budget.findByIdAndUpdate(req.params.id, updates, {
        new: true,
        runValidators: true,
      });

      logger.info('UpdateBudget: Updated successfully', { budgetId: budget._id });

      res.json({
        success: true,
        message: 'Budget updated successfully',
        budget: budget.getSummary(),
      });
    } catch (error) {
      logger.error('UpdateBudget error', { error: error.message });
      res.status(500).json({
        success: false,
        message: 'Failed to update budget',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }
);

/**
 * @route   PATCH /api/budgets/:id/spent
 * @desc    Update spent amount for budget
 * @access  Private
 */
router.patch(
  '/:id/spent',
  protect,
  rateLimiter.general,
  spentValidation,
  validateRequest,
  async (req, res) => {
    try {
      const budget = await Budget.findById(req.params.id);

      if (!budget) {
        logger.warn('UpdateSpent: Budget not found', { budgetId: req.params.id });
        return res.status(404).json({
          success: false,
          message: 'Budget not found',
        });
      }

      if (budget.userId.toString() !== req.user._id.toString()) {
        logger.warn('UpdateSpent: Unauthorized', { budgetId: req.params.id });
        return res.status(403).json({
          success: false,
          message: 'Not authorized',
        });
      }

      if (budget.type !== 'expense') {
        return res.status(400).json({
          success: false,
          message: 'Can only update spent amount for expense entries',
        });
      }

      logger.info('UpdateSpent: Update attempt', { budgetId: budget._id });

      await budget.updateSpent(req.body.spent, req.user._id);

      logger.info('UpdateSpent: Updated successfully', { budgetId: budget._id });

      res.json({
        success: true,
        message: 'Spent amount updated successfully',
        budget: budget.getSummary(),
      });
    } catch (error) {
      logger.error('UpdateSpent error', { error: error.message });
      res.status(500).json({
        success: false,
        message: 'Failed to update spent amount',
      });
    }
  }
);

/**
 * @route   PATCH /api/budgets/:id/reset
 * @desc    Reset budget (set spent to 0)
 * @access  Private
 */
router.patch('/:id/reset', protect, rateLimiter.general, async (req, res) => {
  try {
    const budget = await Budget.findById(req.params.id);

    if (!budget) {
      return res.status(404).json({
        success: false,
        message: 'Budget not found',
      });
    }

    if (budget.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    if (budget.type !== 'expense') {
      return res.status(400).json({
        success: false,
        message: 'Can only reset expense budgets',
      });
    }

    logger.info('ResetBudget: Reset attempt', { budgetId: budget._id });

    await budget.reset(req.user._id);

    logger.info('ResetBudget: Reset successfully', { budgetId: budget._id });

    res.json({
      success: true,
      message: 'Budget reset successfully',
      budget: budget.getSummary(),
    });
  } catch (error) {
    logger.error('ResetBudget error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to reset budget',
    });
  }
});

// ============= DELETE ROUTES =============

/**
 * @route   DELETE /api/budgets/:id
 * @desc    Delete budget
 * @access  Private
 */
router.delete('/:id', protect, rateLimiter.general, async (req, res) => {
  try {
    const budget = await Budget.findById(req.params.id);

    if (!budget) {
      logger.warn('DeleteBudget: Budget not found', { budgetId: req.params.id });
      return res.status(404).json({
        success: false,
        message: 'Budget not found',
      });
    }

    if (budget.userId.toString() !== req.user._id.toString()) {
      logger.warn('DeleteBudget: Unauthorized', { budgetId: req.params.id });
      return res.status(403).json({
        success: false,
        message: 'Not authorized to delete this budget',
      });
    }

    logger.info('DeleteBudget: Delete attempt', { budgetId: budget._id });

    await Budget.findByIdAndDelete(req.params.id);

    logger.info('DeleteBudget: Deleted successfully', { budgetId: req.params.id });

    res.json({
      success: true,
      message: `${budget.type === 'income' ? 'Income' : 'Budget'} deleted successfully`,
    });
  } catch (error) {
    logger.error('DeleteBudget error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to delete budget',
    });
  }
});

// ============= ERROR HANDLING MIDDLEWARE =============

router.use((err, req, res, next) => {
  logger.error('Budget route error', { error: err.message });
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'An error occurred',
    error: process.env.NODE_ENV === 'development' ? err : undefined,
  });
});

module.exports = router;
