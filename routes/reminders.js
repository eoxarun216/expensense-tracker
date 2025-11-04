// File: routes/reminderRoutes.js

const express = require('express');
const router = express.Router();
const { body, query, validationResult } = require('express-validator');
const logger = require('../utils/logger');

// Controllers
const {
  getReminders,
  getReminder,
  createReminder,
  updateReminder,
  deleteReminder,
  markReminderPaid,
  markReminderUnpaid,
  skipReminder,
  pauseReminder,
  resumeReminder,
  getStatistics,
  getOverdue,
  getUpcoming,
  getDueToday,
  getByType,
  getByPriority,
  getRecurring,
  getNotificationQueue,
  markAsNotified,
  bulkMarkPaid,
  bulkDeleteReminders,
  searchReminders,
  exportReminders,
  getPaymentHistory,
  calculateNextOccurrence,
  linkToExpense,
  unlinkFromExpense,
  getLinkedExpenses,
} = require('../controllers/reminderController');

// Middleware
const { protect, authorize } = require('../middleware/auth');
const rateLimiter = require('../middleware/rateLimiter');
const validateRequest = require('../middleware/validateRequest');

// ============= VALIDATION SCHEMAS =============

const createReminderValidation = [
  body('title')
    .trim()
    .notEmpty()
    .withMessage('Title is required')
    .isLength({ min: 1, max: 100 })
    .withMessage('Title must be between 1 and 100 characters'),
  body('type')
    .notEmpty()
    .withMessage('Type is required')
    .isIn([
      'EMI',
      'Mobile Recharge',
      'TV Recharge',
      'Utility Bill',
      'Credit Card',
      'Insurance',
      'Rent',
      'Subscription',
      'Loan Payment',
      'Investment',
      'Custom',
    ])
    .withMessage('Invalid reminder type'),
  body('amount')
    .notEmpty()
    .withMessage('Amount is required')
    .isFloat({ min: 0.01, max: 999999999.99 })
    .withMessage('Amount must be between 0.01 and 999,999,999.99'),
  body('dueDate')
    .notEmpty()
    .withMessage('Due date is required')
    .isISO8601()
    .withMessage('Due date must be a valid ISO 8601 date'),
  body('frequency')
    .optional()
    .isIn(['One-time', 'Daily', 'Weekly', 'Bi-weekly', 'Monthly', 'Quarterly', 'Yearly', 'Custom'])
    .withMessage('Invalid frequency'),
  body('status')
    .optional()
    .isIn(['active', 'completed', 'overdue', 'skipped', 'cancelled', 'paused', 'draft'])
    .withMessage('Invalid status'),
  body('priority')
    .optional()
    .isIn(['critical', 'high', 'medium', 'low'])
    .withMessage('Invalid priority'),
  body('remindDaysBefore')
    .optional()
    .isInt({ min: 0, max: 365 })
    .withMessage('Remind days before must be between 0 and 365'),
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
  body('category')
    .optional()
    .trim(),
  body('vendor')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Vendor name cannot exceed 100 characters'),
];

const updateReminderValidation = [
  body('title')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Title cannot be empty')
    .isLength({ max: 100 }),
  body('amount')
    .optional()
    .isFloat({ min: 0.01 })
    .withMessage('Amount must be positive'),
  body('dueDate')
    .optional()
    .isISO8601()
    .withMessage('Due date must be valid'),
  body('frequency')
    .optional()
    .isIn(['One-time', 'Daily', 'Weekly', 'Bi-weekly', 'Monthly', 'Quarterly', 'Yearly', 'Custom']),
  body('status')
    .optional()
    .isIn(['active', 'completed', 'overdue', 'skipped', 'cancelled', 'paused', 'draft']),
];

const filterValidation = [
  query('type').optional().trim(),
  query('status')
    .optional()
    .isIn(['active', 'completed', 'overdue', 'skipped', 'cancelled', 'paused', 'draft']),
  query('priority')
    .optional()
    .isIn(['critical', 'high', 'medium', 'low']),
  query('frequency').optional().trim(),
  query('from').optional().isISO8601(),
  query('to').optional().isISO8601(),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('sortBy')
    .optional()
    .isIn(['dueDate', 'amount', 'priority', 'createdAt']),
];

const markPaidValidation = [
  body('paidAmount')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Paid amount must be positive'),
  body('paymentReference')
    .optional()
    .trim()
    .isLength({ max: 100 }),
  body('paymentDate')
    .optional()
    .isISO8601(),
];

const bulkOperationValidation = [
  body('reminderIds')
    .isArray({ min: 1 })
    .withMessage('Reminder IDs must be a non-empty array'),
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

// ============= CORE GET ROUTES - ORDER MATTERS =============

/**
 * @route   GET /api/reminders/statistics/overview
 * @desc    Get reminder statistics
 * @access  Private
 */
router.get('/statistics/overview', protect, rateLimiter.general, getStatistics);

/**
 * @route   GET /api/reminders/status/overdue
 * @desc    Get overdue reminders
 * @access  Private
 */
router.get('/status/overdue', protect, rateLimiter.general, async (req, res) => {
  try {
    logger.info('GetOverdue: Request received', { userId: req.user._id });

    const { page = 1, limit = 20, sortBy = 'dueDate' } = req.query;
    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const reminders = await getOverdue(req.user._id, skip, limitNum, sortBy);
    const total = await require('../models/Reminder').countDocuments({
      userId: req.user._id,
      dueDate: { $lt: new Date() },
      status: { $ne: 'completed' },
      deletedAt: null,
    });

    logger.info('GetOverdue: Retrieved successfully', {
      userId: req.user._id,
      count: reminders.length,
    });

    res.json({
      success: true,
      data: {
        reminders,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('GetOverdue error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve overdue reminders',
    });
  }
});

/**
 * @route   GET /api/reminders/status/upcoming
 * @desc    Get upcoming reminders
 * @access  Private
 */
router.get('/status/upcoming', protect, rateLimiter.general, async (req, res) => {
  try {
    logger.info('GetUpcoming: Request received', { userId: req.user._id });

    const { days = 7, page = 1, limit = 20 } = req.query;
    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const reminders = await getUpcoming(req.user._id, parseInt(days), skip, limitNum);
    const total = await require('../models/Reminder').countDocuments({
      userId: req.user._id,
      dueDate: {
        $gte: new Date(),
        $lte: new Date(Date.now() + parseInt(days) * 24 * 60 * 60 * 1000),
      },
      status: { $ne: 'completed' },
      deletedAt: null,
    });

    logger.info('GetUpcoming: Retrieved successfully', {
      userId: req.user._id,
      count: reminders.length,
    });

    res.json({
      success: true,
      data: {
        reminders,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('GetUpcoming error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve upcoming reminders',
    });
  }
});

/**
 * @route   GET /api/reminders/status/today
 * @desc    Get reminders due today
 * @access  Private
 */
router.get('/status/today', protect, rateLimiter.general, getDueToday);

/**
 * @route   GET /api/reminders/by-type
 * @desc    Get reminders by type
 * @access  Private
 */
router.get(
  '/by-type',
  protect,
  rateLimiter.general,
  query('type').notEmpty().withMessage('Type is required'),
  validateRequest,
  getByType
);

/**
 * @route   GET /api/reminders/by-priority
 * @desc    Get reminders by priority
 * @access  Private
 */
router.get(
  '/by-priority',
  protect,
  rateLimiter.general,
  query('priority')
    .notEmpty()
    .withMessage('Priority is required')
    .isIn(['critical', 'high', 'medium', 'low']),
  validateRequest,
  getByPriority
);

/**
 * @route   GET /api/reminders/recurring
 * @desc    Get recurring reminders
 * @access  Private
 */
router.get('/recurring', protect, rateLimiter.general, getRecurring);

/**
 * @route   GET /api/reminders/notifications/queue
 * @desc    Get reminders that need notification
 * @access  Private
 */
router.get('/notifications/queue', protect, rateLimiter.general, getNotificationQueue);

/**
 * @route   GET /api/reminders/search
 * @desc    Search reminders
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
  searchReminders
);

/**
 * @route   GET /api/reminders/export
 * @desc    Export reminders
 * @access  Private
 */
router.get(
  '/export',
  protect,
  rateLimiter.general,
  query('format').optional().isIn(['json', 'csv']),
  validateRequest,
  exportReminders
);

/**
 * @route   GET /api/reminders/payments/history
 * @desc    Get payment history
 * @access  Private
 */
router.get('/payments/history', protect, rateLimiter.general, getPaymentHistory);

/**
 * @route   GET /api/reminders/:id/expenses
 * @desc    Get linked expenses for reminder
 * @access  Private
 */
router.get('/:id/expenses', protect, rateLimiter.general, getLinkedExpenses);

/**
 * @route   GET /api/reminders/summary
 * @desc    Get reminder summary statistics
 * @access  Private
 */
router.get('/summary/all', protect, rateLimiter.general, async (req, res) => {
  try {
    logger.info('GetSummary: Request received', { userId: req.user._id });

    const Reminder = require('../models/Reminder');
    const stats = await Reminder.getStatistics(req.user._id);

    logger.info('GetSummary: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      summary: stats,
    });
  } catch (error) {
    logger.error('GetSummary error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve summary',
    });
  }
});

// ============= PAYMENT STATUS ROUTES =============

/**
 * @route   POST /api/reminders/:id/mark-paid
 * @desc    Mark reminder as paid
 * @access  Private
 */
router.post(
  '/:id/mark-paid',
  protect,
  rateLimiter.general,
  markPaidValidation,
  validateRequest,
  markReminderPaid
);

/**
 * @route   POST /api/reminders/:id/mark-unpaid
 * @desc    Mark reminder as unpaid (revert payment)
 * @access  Private
 */
router.post('/:id/mark-unpaid', protect, rateLimiter.general, markReminderUnpaid);

/**
 * @route   POST /api/reminders/:id/skip
 * @desc    Skip reminder
 * @access  Private
 */
router.post('/:id/skip', protect, rateLimiter.general, skipReminder);

/**
 * @route   POST /api/reminders/:id/pause
 * @desc    Pause reminder
 * @access  Private
 */
router.post('/:id/pause', protect, rateLimiter.general, pauseReminder);

/**
 * @route   POST /api/reminders/:id/resume
 * @desc    Resume paused reminder
 * @access  Private
 */
router.post('/:id/resume', protect, rateLimiter.general, resumeReminder);

/**
 * @route   POST /api/reminders/:id/mark-notified
 * @desc    Mark reminder as notified
 * @access  Private
 */
router.post('/:id/mark-notified', protect, rateLimiter.general, markAsNotified);

// ============= LINKING ROUTES =============

/**
 * @route   POST /api/reminders/:id/link-expense
 * @desc    Link expense to reminder
 * @access  Private
 */
router.post(
  '/:id/link-expense',
  protect,
  rateLimiter.general,
  body('expenseId').notEmpty().withMessage('Expense ID is required'),
  validateRequest,
  linkToExpense
);

/**
 * @route   POST /api/reminders/:id/unlink-expense
 * @desc    Unlink expense from reminder
 * @access  Private
 */
router.post('/:id/unlink-expense', protect, rateLimiter.general, unlinkFromExpense);

/**
 * @route   POST /api/reminders/:id/next-occurrence
 * @desc    Calculate next occurrence for recurring reminder
 * @access  Private
 */
router.post('/:id/next-occurrence', protect, rateLimiter.general, calculateNextOccurrence);

// ============= BULK OPERATIONS =============

/**
 * @route   POST /api/reminders/bulk/mark-paid
 * @desc    Bulk mark reminders as paid
 * @access  Private
 */
router.post(
  '/bulk/mark-paid',
  protect,
  rateLimiter.general,
  bulkOperationValidation,
  validateRequest,
  bulkMarkPaid
);

/**
 * @route   DELETE /api/reminders/bulk/delete
 * @desc    Bulk delete reminders
 * @access  Private
 */
router.delete(
  '/bulk/delete',
  protect,
  rateLimiter.general,
  bulkOperationValidation,
  validateRequest,
  bulkDeleteReminders
);

// ============= MAIN CRUD ROUTES =============

/**
 * @route   GET /api/reminders
 * @desc    Get all reminders with filters
 * @access  Private
 */
router.get(
  '/',
  protect,
  rateLimiter.general,
  filterValidation,
  validateRequest,
  getReminders
);

/**
 * @route   POST /api/reminders
 * @desc    Create new reminder
 * @access  Private
 */
router.post(
  '/',
  protect,
  rateLimiter.general,
  createReminderValidation,
  validateRequest,
  createReminder
);

/**
 * @route   GET /api/reminders/:id
 * @desc    Get single reminder
 * @access  Private
 */
router.get('/:id', protect, rateLimiter.general, getReminder);

/**
 * @route   PUT /api/reminders/:id
 * @desc    Update reminder
 * @access  Private
 */
router.put(
  '/:id',
  protect,
  rateLimiter.general,
  updateReminderValidation,
  validateRequest,
  updateReminder
);

/**
 * @route   DELETE /api/reminders/:id
 * @desc    Delete reminder (soft delete)
 * @access  Private
 */
router.delete('/:id', protect, rateLimiter.general, deleteReminder);

// ============= ERROR HANDLING MIDDLEWARE =============

router.use((err, req, res, next) => {
  logger.error('Reminder route error', { error: err.message, stack: err.stack });
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'An error occurred',
    error: process.env.NODE_ENV === 'development' ? err : undefined,
  });
});

module.exports = router;
