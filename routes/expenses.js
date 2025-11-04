// File: routes/expenseRoutes.js

const express = require('express');
const router = express.Router();
const { body, query, validationResult } = require('express-validator');
const logger = require('../utils/logger');

// Controllers
const {
  getExpenses,
  getExpense,
  createExpense,
  updateExpense,
  deleteExpense,
  getStatistics,
  bulkDeleteExpenses,
  exportExpenses,
  getExpensesByCategory,
  getExpensesByDateRange,
  getExpensesByPaymentMethod,
  searchExpenses,
  getRecentExpenses,
  getHighSpendingAlerts,
  getSpendingTrend,
  getDailyAverageSpending,
  getMonthlyAnalysis,
  linkToReminder,
  markForReimbursement,
  updateReimbursementStatus,
  bulkUpdateReimbursement,
} = require('../controllers/expenseController');

// Middleware
const { protect, authorize } = require('../middleware/auth');
const rateLimiter = require('../middleware/rateLimiter');
const validateRequest = require('../middleware/validateRequest');

// ============= VALIDATION SCHEMAS =============

const createExpenseValidation = [
  body('title')
    .trim()
    .notEmpty()
    .withMessage('Title is required')
    .isLength({ min: 1, max: 100 })
    .withMessage('Title must be between 1 and 100 characters'),
  body('amount')
    .notEmpty()
    .withMessage('Amount is required')
    .isFloat({ min: 0.01, max: 999999999.99 })
    .withMessage('Amount must be between 0.01 and 999,999,999.99'),
  body('category')
    .notEmpty()
    .withMessage('Category is required'),
  body('date')
    .optional()
    .isISO8601()
    .withMessage('Date must be a valid ISO 8601 date'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters'),
  body('paymentMethod')
    .optional()
    .isIn(['cash', 'credit_card', 'debit_card', 'upi', 'bank_transfer', 'wallet', 'cheque', 'other'])
    .withMessage('Invalid payment method'),
  body('vendor')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Vendor name cannot exceed 100 characters'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Notes cannot exceed 1000 characters'),
];

const updateExpenseValidation = [
  body('title')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Title cannot be empty')
    .isLength({ max: 100 })
    .withMessage('Title cannot exceed 100 characters'),
  body('amount')
    .optional()
    .isFloat({ min: 0.01 })
    .withMessage('Amount must be positive'),
  body('category')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Category cannot be empty'),
  body('date')
    .optional()
    .isISO8601()
    .withMessage('Date must be valid'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters'),
  body('paymentMethod')
    .optional()
    .isIn(['cash', 'credit_card', 'debit_card', 'upi', 'bank_transfer', 'wallet', 'cheque', 'other'])
    .withMessage('Invalid payment method'),
];

const filterValidation = [
  query('category')
    .optional()
    .trim(),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be valid'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be valid'),
  query('paymentMethod')
    .optional()
    .isIn(['cash', 'credit_card', 'debit_card', 'upi', 'bank_transfer', 'wallet', 'cheque', 'other']),
  query('search')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Search term must be between 1 and 100 characters'),
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('sortBy')
    .optional()
    .isIn(['date', 'amount', 'amount_asc', 'amount_desc', 'date_asc', 'date_desc'])
    .withMessage('Invalid sort option'),
];

const reimbursementValidation = [
  body('status')
    .notEmpty()
    .withMessage('Status is required')
    .isIn(['pending', 'approved', 'rejected', 'reimbursed'])
    .withMessage('Invalid reimbursement status'),
];

const bulkDeleteValidation = [
  body('expenseIds')
    .isArray({ min: 1 })
    .withMessage('Expense IDs must be a non-empty array'),
];

const bulkReimbursementValidation = [
  body('expenseIds')
    .isArray({ min: 1 })
    .withMessage('Expense IDs must be a non-empty array'),
  body('status')
    .notEmpty()
    .withMessage('Status is required')
    .isIn(['pending', 'approved', 'rejected', 'reimbursed'])
    .withMessage('Invalid status'),
];

// ============= HELPER FUNCTIONS =============

const getPagination = (page = 1, limit = 20) => {
  const pageNum = Math.max(1, parseInt(page));
  const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
  return {
    skip: (pageNum - 1) * limitNum,
    limit: limitNum,
    page: pageNum,
  };
};

// ============= CORE ROUTES - ORDER MATTERS =============

/**
 * @route   GET /api/expenses/statistics/overview
 * @desc    Get spending statistics (must be before :id route)
 * @access  Private
 */
router.get('/statistics/overview', protect, rateLimiter.general, getStatistics);

/**
 * @route   GET /api/expenses/analytics/trend
 * @desc    Get spending trend
 * @access  Private
 */
router.get(
  '/analytics/trend',
  protect,
  rateLimiter.general,
  query('days').optional().isInt({ min: 1, max: 365 }),
  validateRequest,
  getSpendingTrend
);

/**
 * @route   GET /api/expenses/analytics/average
 * @desc    Get daily average spending
 * @access  Private
 */
router.get(
  '/analytics/average',
  protect,
  rateLimiter.general,
  query('days').optional().isInt({ min: 1, max: 365 }),
  validateRequest,
  getDailyAverageSpending
);

/**
 * @route   GET /api/expenses/analytics/monthly
 * @desc    Get monthly analysis
 * @access  Private
 */
router.get(
  '/analytics/monthly',
  protect,
  rateLimiter.general,
  query('year').optional().isInt({ min: 2000, max: 2100 }),
  validateRequest,
  getMonthlyAnalysis
);

/**
 * @route   GET /api/expenses/analytics/alerts
 * @desc    Get high spending alerts
 * @access  Private
 */
router.get(
  '/analytics/alerts',
  protect,
  rateLimiter.general,
  query('threshold').notEmpty().isFloat({ min: 0 }),
  validateRequest,
  getHighSpendingAlerts
);

/**
 * @route   GET /api/expenses/recent
 * @desc    Get recent expenses
 * @access  Private
 */
router.get(
  '/recent',
  protect,
  rateLimiter.general,
  query('days').optional().isInt({ min: 1, max: 365 }),
  validateRequest,
  getRecentExpenses
);

/**
 * @route   GET /api/expenses/search
 * @desc    Search expenses
 * @access  Private
 */
router.get(
  '/search',
  protect,
  rateLimiter.general,
  query('q')
    .notEmpty()
    .withMessage('Search query is required')
    .trim()
    .isLength({ min: 1, max: 100 }),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  validateRequest,
  searchExpenses
);

/**
 * @route   GET /api/expenses/by-category
 * @desc    Get expenses by category
 * @access  Private
 */
router.get(
  '/by-category',
  protect,
  rateLimiter.general,
  query('category').notEmpty().withMessage('Category is required'),
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  validateRequest,
  getExpensesByCategory
);

/**
 * @route   GET /api/expenses/by-date
 * @desc    Get expenses by date range
 * @access  Private
 */
router.get(
  '/by-date',
  protect,
  rateLimiter.general,
  query('startDate').notEmpty().isISO8601().withMessage('Valid start date required'),
  query('endDate').notEmpty().isISO8601().withMessage('Valid end date required'),
  validateRequest,
  getExpensesByDateRange
);

/**
 * @route   GET /api/expenses/by-payment
 * @desc    Get expenses by payment method
 * @access  Private
 */
router.get(
  '/by-payment',
  protect,
  rateLimiter.general,
  query('method')
    .notEmpty()
    .withMessage('Payment method is required')
    .isIn(['cash', 'credit_card', 'debit_card', 'upi', 'bank_transfer', 'wallet', 'cheque', 'other']),
  validateRequest,
  getExpensesByPaymentMethod
);

/**
 * @route   GET /api/expenses/export
 * @desc    Export expenses
 * @access  Private
 */
router.get(
  '/export',
  protect,
  rateLimiter.general,
  query('format').optional().isIn(['json', 'csv']),
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  validateRequest,
  exportExpenses
);

// ============= REIMBURSEMENT ROUTES =============

/**
 * @route   GET /api/expenses/reimbursement/pending
 * @desc    Get pending reimbursement expenses
 * @access  Private
 */
router.get('/reimbursement/pending', protect, rateLimiter.general, async (req, res) => {
  try {
    logger.info('GetPendingReimbursement: Request received', { userId: req.user._id });

    const Expense = require('../models/Expense');
    const { page = 1, limit = 20 } = req.query;
    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const expenses = await Expense.getReimbursable(req.user._id, 'pending')
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Expense.countDocuments({
      user: req.user._id,
      isReimbursable: true,
      reimbursementStatus: 'pending',
      deletedAt: null,
    });

    logger.info('GetPendingReimbursement: Retrieved successfully', {
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
    logger.error('GetPendingReimbursement error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve pending reimbursements',
    });
  }
});

/**
 * @route   POST /api/expenses/:id/mark-reimbursable
 * @desc    Mark expense for reimbursement
 * @access  Private
 */
router.post('/:id/mark-reimbursable', protect, rateLimiter.general, markForReimbursement);

/**
 * @route   PATCH /api/expenses/:id/reimbursement-status
 * @desc    Update reimbursement status
 * @access  Private
 */
router.patch(
  '/:id/reimbursement-status',
  protect,
  rateLimiter.general,
  reimbursementValidation,
  validateRequest,
  updateReimbursementStatus
);

/**
 * @route   PATCH /api/expenses/bulk/reimbursement-status
 * @desc    Bulk update reimbursement status
 * @access  Private
 */
router.patch(
  '/bulk/reimbursement-status',
  protect,
  rateLimiter.general,
  bulkReimbursementValidation,
  validateRequest,
  bulkUpdateReimbursement
);

// ============= REMINDER LINKING ROUTES =============

/**
 * @route   POST /api/expenses/:id/link-reminder
 * @desc    Link expense to reminder
 * @access  Private
 */
router.post(
  '/:id/link-reminder',
  protect,
  rateLimiter.general,
  body('reminderId').notEmpty().withMessage('Reminder ID is required'),
  validateRequest,
  linkToReminder
);

// ============= BULK OPERATIONS =============

/**
 * @route   DELETE /api/expenses/bulk/delete
 * @desc    Bulk delete expenses
 * @access  Private
 */
router.delete(
  '/bulk/delete',
  protect,
  rateLimiter.general,
  bulkDeleteValidation,
  validateRequest,
  bulkDeleteExpenses
);

// ============= MAIN CRUD ROUTES =============

/**
 * @route   GET /api/expenses
 * @desc    Get all expenses with filters and pagination
 * @access  Private
 */
router.get(
  '/',
  protect,
  rateLimiter.general,
  filterValidation,
  validateRequest,
  getExpenses
);

/**
 * @route   POST /api/expenses
 * @desc    Create new expense
 * @access  Private
 */
router.post(
  '/',
  protect,
  rateLimiter.general,
  createExpenseValidation,
  validateRequest,
  createExpense
);

/**
 * @route   GET /api/expenses/:id
 * @desc    Get single expense
 * @access  Private
 */
router.get('/:id', protect, rateLimiter.general, getExpense);

/**
 * @route   PUT /api/expenses/:id
 * @desc    Update expense
 * @access  Private
 */
router.put(
  '/:id',
  protect,
  rateLimiter.general,
  updateExpenseValidation,
  validateRequest,
  updateExpense
);

/**
 * @route   DELETE /api/expenses/:id
 * @desc    Delete expense (soft delete)
 * @access  Private
 */
router.delete('/:id', protect, rateLimiter.general, deleteExpense);

// ============= ERROR HANDLING MIDDLEWARE =============

router.use((err, req, res, next) => {
  logger.error('Expense route error', { error: err.message, stack: err.stack });
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'An error occurred',
    error: process.env.NODE_ENV === 'development' ? err : undefined,
  });
});

module.exports = router;
