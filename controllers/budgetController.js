// File: controllers/budgetController.js

const Budget = require('../models/Budget');
const logger = require('../utils/logger');

// ============= CONSTANTS =============

const BUDGET_TYPES = {
  EXPENSE: 'expense',
  INCOME: 'income',
};

const BUDGET_PERIODS = {
  WEEKLY: 'weekly',
  MONTHLY: 'monthly',
  YEARLY: 'yearly',
};

// ============= HELPER FUNCTIONS =============

/**
 * Build budget response
 */
const buildBudgetResponse = (budget) => ({
  id: budget._id,
  category: budget.category,
  type: budget.type,
  period: budget.period,
  ...(budget.type === BUDGET_TYPES.EXPENSE && {
    limit: budget.limit,
    spent: budget.spent,
    remaining: budget.remaining,
    usagePercentage: budget.usagePercentage,
    status: budget.status,
  }),
  ...(budget.type === BUDGET_TYPES.INCOME && {
    incomeSource: budget.incomeSource,
    incomeAmount: budget.incomeAmount,
  }),
  alertThreshold: budget.alertThreshold,
  active: budget.active,
  createdAt: budget.createdAt,
  updatedAt: budget.updatedAt,
});

/**
 * Parse pagination
 */
const getPagination = (page = 1, limit = 20) => {
  const pageNum = Math.max(1, parseInt(page));
  const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
  return {
    skip: (pageNum - 1) * limitNum,
    limit: limitNum,
    page: pageNum,
  };
};

// ============= GET CONTROLLERS =============

/**
 * @desc    Get all budgets with filters
 * @route   GET /api/budgets
 * @access  Private
 */
exports.getBudgets = async (req, res) => {
  try {
    const { type, period, category, page = 1, limit = 20 } = req.query;

    logger.info('GetBudgets: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    // Build query
    const query = { userId: req.user._id, active: true };
    if (type) query.type = type;
    if (period) query.period = period;
    if (category) query.category = category;

    // Get budgets
    const budgets = await Budget.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Budget.countDocuments(query);

    logger.info('GetBudgets: Retrieved successfully', {
      userId: req.user._id,
      count: budgets.length,
    });

    res.json({
      success: true,
      data: {
        budgets: budgets.map(buildBudgetResponse),
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('GetBudgets error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve budgets',
    });
  }
};

/**
 * @desc    Get single budget
 * @route   GET /api/budgets/:id
 * @access  Private
 */
exports.getBudget = async (req, res) => {
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
      logger.warn('GetBudget: Unauthorized', { budgetId: req.params.id });
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this budget',
      });
    }

    logger.info('GetBudget: Retrieved successfully', { budgetId: budget._id });

    res.json({
      success: true,
      budget: buildBudgetResponse(budget),
    });
  } catch (error) {
    logger.error('GetBudget error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve budget',
    });
  }
};

/**
 * @desc    Get financial summary
 * @route   GET /api/budgets/summary/all
 * @access  Private
 */
exports.getSummary = async (req, res) => {
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
          ? parseFloat((((totalIncome - totalExpenses) / totalIncome) * 100).toFixed(2))
          : 0,
        incomeBreakdown,
        expenseBreakdown,
        financialHealth,
      },
    });
  } catch (error) {
    logger.error('GetSummary error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve summary',
    });
  }
};

/**
 * @desc    Get income breakdown
 * @route   GET /api/budgets/analytics/income-breakdown
 * @access  Private
 */
exports.getIncomeBreakdown = async (req, res) => {
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
};

/**
 * @desc    Get expense breakdown
 * @route   GET /api/budgets/analytics/expense-breakdown
 * @access  Private
 */
exports.getExpenseBreakdown = async (req, res) => {
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
};

/**
 * @desc    Get financial health
 * @route   GET /api/budgets/analytics/health
 * @access  Private
 */
exports.getHealth = async (req, res) => {
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
};

/**
 * @desc    Get category summary
 * @route   GET /api/budgets/analytics/category-summary
 * @access  Private
 */
exports.getCategorySummary = async (req, res) => {
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
};

/**
 * @desc    Get warning budgets
 * @route   GET /api/budgets/analytics/warnings
 * @access  Private
 */
exports.getWarnings = async (req, res) => {
  try {
    logger.info('GetWarnings: Request received', { userId: req.user._id });

    const warnings = await Budget.getWarningBudgets(req.user._id);

    logger.info('GetWarnings: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      warnings: warnings.map(buildBudgetResponse),
    });
  } catch (error) {
    logger.error('GetWarnings error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve warnings',
    });
  }
};

/**
 * @desc    Get exceeded budgets
 * @route   GET /api/budgets/analytics/exceeded
 * @access  Private
 */
exports.getExceeded = async (req, res) => {
  try {
    logger.info('GetExceeded: Request received', { userId: req.user._id });

    const exceeded = await Budget.getExceededBudgets(req.user._id);

    logger.info('GetExceeded: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      exceeded: exceeded.map(buildBudgetResponse),
    });
  } catch (error) {
    logger.error('GetExceeded error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve exceeded budgets',
    });
  }
};

// ============= CREATE CONTROLLER =============

/**
 * @desc    Create new budget
 * @route   POST /api/budgets
 * @access  Private
 */
exports.createBudget = async (req, res) => {
  try {
    const {
      category,
      limit,
      period = 'monthly',
      type = 'expense',
      incomeSource,
      incomeAmount,
      description,
      notes,
      alertThreshold = 80,
    } = req.body;

    logger.info('CreateBudget: Request received', { userId: req.user._id, type });

    // Check if entry already exists
    const query = {
      userId: req.user._id,
      category,
      period,
      type,
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
      period,
      type,
      description,
      notes,
      alertThreshold,
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
      budget: buildBudgetResponse(budget),
    });
  } catch (error) {
    logger.error('CreateBudget error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to create budget',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

/**
 * @desc    Create personal income
 * @route   POST /api/budgets/income/personal
 * @access  Private
 */
exports.createPersonalIncome = async (req, res) => {
  try {
    const { amount, period = 'monthly' } = req.body;

    logger.info('CreatePersonalIncome: Request received', { userId: req.user._id });

    let income = await Budget.findOne({
      userId: req.user._id,
      type: 'income',
      incomeSource: 'personal',
      period,
      active: true,
    });

    if (income) {
      await income.updateIncome(amount, req.user._id);
    } else {
      income = await Budget.create({
        userId: req.user._id,
        category: 'Personal Income',
        type: 'income',
        incomeSource: 'personal',
        incomeAmount: amount,
        period,
        limit: 0,
        spent: 0,
      });
    }

    logger.info('CreatePersonalIncome: Saved successfully', { budgetId: income._id });

    res.status(201).json({
      success: true,
      message: 'Personal income set successfully',
      budget: buildBudgetResponse(income),
    });
  } catch (error) {
    logger.error('CreatePersonalIncome error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to set personal income',
    });
  }
};

/**
 * @desc    Create family income
 * @route   POST /api/budgets/income/family
 * @access  Private
 */
exports.createFamilyIncome = async (req, res) => {
  try {
    const { amount, period = 'monthly' } = req.body;

    logger.info('CreateFamilyIncome: Request received', { userId: req.user._id });

    let income = await Budget.findOne({
      userId: req.user._id,
      type: 'income',
      incomeSource: 'family',
      period,
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
        period,
        limit: 0,
        spent: 0,
      });
    }

    logger.info('CreateFamilyIncome: Saved successfully', { budgetId: income._id });

    res.status(201).json({
      success: true,
      message: 'Family income set successfully',
      budget: buildBudgetResponse(income),
    });
  } catch (error) {
    logger.error('CreateFamilyIncome error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to set family income',
    });
  }
};

// ============= UPDATE CONTROLLER =============

/**
 * @desc    Update budget
 * @route   PUT /api/budgets/:id
 * @access  Private
 */
exports.updateBudget = async (req, res) => {
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
    const allowedFields = [
      'category',
      'limit',
      'spent',
      'period',
      'alertThreshold',
      'description',
      'notes',
      'incomeAmount',
      'notifyOnExceed',
    ];

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
      budget: buildBudgetResponse(budget),
    });
  } catch (error) {
    logger.error('UpdateBudget error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to update budget',
    });
  }
};

/**
 * @desc    Update spent amount
 * @route   PATCH /api/budgets/:id/spent
 * @access  Private
 */
exports.updateSpent = async (req, res) => {
  try {
    const { spent } = req.body;

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

    await budget.updateSpent(spent, req.user._id);

    logger.info('UpdateSpent: Updated successfully', { budgetId: budget._id });

    res.json({
      success: true,
      message: 'Spent amount updated successfully',
      budget: buildBudgetResponse(budget),
    });
  } catch (error) {
    logger.error('UpdateSpent error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to update spent amount',
    });
  }
};

/**
 * @desc    Reset budget
 * @route   PATCH /api/budgets/:id/reset
 * @access  Private
 */
exports.resetBudget = async (req, res) => {
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
      budget: buildBudgetResponse(budget),
    });
  } catch (error) {
    logger.error('ResetBudget error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to reset budget',
    });
  }
};

// ============= DELETE CONTROLLER =============

/**
 * @desc    Delete budget
 * @route   DELETE /api/budgets/:id
 * @access  Private
 */
exports.deleteBudget = async (req, res) => {
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
};
