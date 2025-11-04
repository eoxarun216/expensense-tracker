// File: controllers/expenseController.js

const Expense = require('../models/Expense');
const logger = require('../utils/logger');

// ============= HELPER FUNCTIONS =============

/**
 * Build expense response
 */
const buildExpenseResponse = (expense) => ({
  id: expense._id,
  title: expense.title,
  amount: expense.amount,
  formattedAmount: `₹${expense.amount.toFixed(2)}`,
  category: expense.category,
  category_group: expense.category_group,
  date: expense.date,
  formattedDate: new Date(expense.date).toLocaleDateString('en-IN'),
  description: expense.description,
  paymentMethod: expense.paymentMethod,
  vendor: expense.vendor,
  tags: expense.tags,
  notes: expense.notes,
  isRecurring: expense.isRecurring,
  isBillPayment: expense.isBillPayment,
  isReimbursable: expense.isReimbursable,
  reimbursementStatus: expense.reimbursementStatus,
  createdAt: expense.createdAt,
  updatedAt: expense.updatedAt,
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
 * @desc    Get all expenses with filters
 * @route   GET /api/expenses
 * @access  Private
 */
exports.getExpenses = async (req, res) => {
  try {
    const {
      category,
      startDate,
      endDate,
      paymentMethod,
      search,
      page = 1,
      limit = 20,
      sortBy = 'date',
    } = req.query;

    logger.info('GetExpenses: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    // Build query
    const query = { user: req.user._id, deletedAt: null };

    if (category) query.category = category;
    if (paymentMethod) query.paymentMethod = paymentMethod;

    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) {
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        query.date.$lte = end;
      }
    }

    // Handle search
    if (search) {
      query.$or = [
        { title: new RegExp(search, 'i') },
        { description: new RegExp(search, 'i') },
        { vendor: new RegExp(search, 'i') },
      ];
    }

    // Build sort
    const sortOptions = {};
    switch (sortBy) {
      case 'amount':
        sortOptions.amount = -1;
        break;
      case 'amount_asc':
        sortOptions.amount = 1;
        break;
      case 'date_asc':
        sortOptions.date = 1;
        break;
      default:
        sortOptions.date = -1;
    }

    const expenses = await Expense.find(query)
      .sort(sortOptions)
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Expense.countDocuments(query);

    logger.info('GetExpenses: Retrieved successfully', {
      userId: req.user._id,
      count: expenses.length,
    });

    res.json({
      success: true,
      data: {
        expenses: expenses.map(buildExpenseResponse),
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('GetExpenses error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve expenses',
    });
  }
};

/**
 * @desc    Get single expense
 * @route   GET /api/expenses/:id
 * @access  Private
 */
exports.getExpense = async (req, res) => {
  try {
    const expense = await Expense.findById(req.params.id);

    if (!expense) {
      logger.warn('GetExpense: Expense not found', { expenseId: req.params.id });
      return res.status(404).json({
        success: false,
        message: 'Expense not found',
      });
    }

    if (expense.user.toString() !== req.user._id.toString()) {
      logger.warn('GetExpense: Unauthorized', { expenseId: req.params.id });
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('GetExpense: Retrieved successfully', { expenseId: expense._id });

    res.json({
      success: true,
      expense: buildExpenseResponse(expense),
    });
  } catch (error) {
    logger.error('GetExpense error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve expense',
    });
  }
};

/**
 * @desc    Get expenses by category
 * @route   GET /api/expenses/by-category
 * @access  Private
 */
exports.getExpensesByCategory = async (req, res) => {
  try {
    const { category, startDate, endDate, page = 1, limit = 20 } = req.query;

    logger.info('GetExpensesByCategory: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const query = { user: req.user._id, category, deletedAt: null };

    if (startDate && endDate) {
      query.date = {
        $gte: new Date(startDate),
        $lte: new Date(endDate),
      };
    }

    const expenses = await Expense.find(query)
      .sort({ date: -1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Expense.countDocuments(query);

    logger.info('GetExpensesByCategory: Retrieved successfully', {
      userId: req.user._id,
      count: expenses.length,
    });

    res.json({
      success: true,
      data: {
        expenses: expenses.map(buildExpenseResponse),
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('GetExpensesByCategory error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve expenses',
    });
  }
};

/**
 * @desc    Get expenses by date range
 * @route   GET /api/expenses/by-date
 * @access  Private
 */
exports.getExpensesByDateRange = async (req, res) => {
  try {
    const { startDate, endDate, page = 1, limit = 20 } = req.query;

    logger.info('GetExpensesByDateRange: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const query = {
      user: req.user._id,
      date: {
        $gte: new Date(startDate),
        $lte: new Date(endDate),
      },
      deletedAt: null,
    };

    const expenses = await Expense.find(query)
      .sort({ date: -1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Expense.countDocuments(query);

    logger.info('GetExpensesByDateRange: Retrieved successfully', {
      userId: req.user._id,
      count: expenses.length,
    });

    res.json({
      success: true,
      data: {
        expenses: expenses.map(buildExpenseResponse),
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('GetExpensesByDateRange error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve expenses',
    });
  }
};

/**
 * @desc    Get expenses by payment method
 * @route   GET /api/expenses/by-payment
 * @access  Private
 */
exports.getExpensesByPaymentMethod = async (req, res) => {
  try {
    const { method, page = 1, limit = 20 } = req.query;

    logger.info('GetExpensesByPaymentMethod: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const expenses = await Expense.find({ user: req.user._id, paymentMethod: method, deletedAt: null })
      .sort({ date: -1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Expense.countDocuments({
      user: req.user._id,
      paymentMethod: method,
      deletedAt: null,
    });

    logger.info('GetExpensesByPaymentMethod: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      data: {
        expenses: expenses.map(buildExpenseResponse),
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('GetExpensesByPaymentMethod error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve expenses',
    });
  }
};

/**
 * @desc    Search expenses
 * @route   GET /api/expenses/search
 * @access  Private
 */
exports.searchExpenses = async (req, res) => {
  try {
    const { q, page = 1, limit = 20 } = req.query;

    logger.info('SearchExpenses: Request received', { userId: req.user._id, query: q });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const { results, total } = await Expense.searchExpenses(req.user._id, q, {
      limit: limitNum,
      skip,
    });

    logger.info('SearchExpenses: Retrieved successfully', { userId: req.user._id, count: results.length });

    res.json({
      success: true,
      data: {
        expenses: results.map(buildExpenseResponse),
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('SearchExpenses error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Search failed',
    });
  }
};

/**
 * @desc    Get recent expenses
 * @route   GET /api/expenses/recent
 * @access  Private
 */
exports.getRecentExpenses = async (req, res) => {
  try {
    const { days = 7 } = req.query;

    logger.info('GetRecentExpenses: Request received', { userId: req.user._id, days });

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const expenses = await Expense.find({
      user: req.user._id,
      date: { $gte: startDate },
      deletedAt: null,
    })
      .sort({ date: -1 })
      .limit(20)
      .lean();

    logger.info('GetRecentExpenses: Retrieved successfully', {
      userId: req.user._id,
      count: expenses.length,
    });

    res.json({
      success: true,
      expenses: expenses.map(buildExpenseResponse),
    });
  } catch (error) {
    logger.error('GetRecentExpenses error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve recent expenses',
    });
  }
};

/**
 * @desc    Get spending trend
 * @route   GET /api/expenses/analytics/trend
 * @access  Private
 */
exports.getSpendingTrend = async (req, res) => {
  try {
    const { days = 30 } = req.query;

    logger.info('GetSpendingTrend: Request received', { userId: req.user._id });

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const trend = await Expense.getSpendingTrend(req.user._id, parseInt(days));

    logger.info('GetSpendingTrend: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      trend,
    });
  } catch (error) {
    logger.error('GetSpendingTrend error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve spending trend',
    });
  }
};

/**
 * @desc    Get daily average spending
 * @route   GET /api/expenses/analytics/average
 * @access  Private
 */
exports.getDailyAverageSpending = async (req, res) => {
  try {
    const { days = 30 } = req.query;

    logger.info('GetDailyAverageSpending: Request received', { userId: req.user._id });

    const average = await Expense.getAverageDailySpending(req.user._id, parseInt(days));

    logger.info('GetDailyAverageSpending: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      average,
      days: parseInt(days),
    });
  } catch (error) {
    logger.error('GetDailyAverageSpending error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to calculate average',
    });
  }
};

/**
 * @desc    Get monthly analysis
 * @route   GET /api/expenses/analytics/monthly
 * @access  Private
 */
exports.getMonthlyAnalysis = async (req, res) => {
  try {
    const { year } = req.query;

    logger.info('GetMonthlyAnalysis: Request received', { userId: req.user._id });

    const analysis = await Expense.getMonthlyBreakdown(req.user._id, year ? parseInt(year) : null);

    logger.info('GetMonthlyAnalysis: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      analysis,
    });
  } catch (error) {
    logger.error('GetMonthlyAnalysis error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve monthly analysis',
    });
  }
};

/**
 * @desc    Get high spending alerts
 * @route   GET /api/expenses/analytics/alerts
 * @access  Private
 */
exports.getHighSpendingAlerts = async (req, res) => {
  try {
    const { threshold = 1000 } = req.query;

    logger.info('GetHighSpendingAlerts: Request received', { userId: req.user._id });

    const alerts = await Expense.getHighSpendingAlerts(req.user._id, parseFloat(threshold));

    logger.info('GetHighSpendingAlerts: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      alerts: alerts.map(buildExpenseResponse),
      threshold,
    });
  } catch (error) {
    logger.error('GetHighSpendingAlerts error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve alerts',
    });
  }
};

/**
 * @desc    Get statistics
 * @route   GET /api/expenses/statistics/overview
 * @access  Private
 */
exports.getStatistics = async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    logger.info('GetStatistics: Request received', { userId: req.user._id });

    const query = { user: req.user._id, deletedAt: null };

    if (startDate && endDate) {
      query.date = {
        $gte: new Date(startDate),
        $lte: new Date(endDate),
      };
    }

    const [
      categoryBreakdown,
      paymentMethodBreakdown,
      totalSpent,
      averageExpense,
      highestExpense,
      expenseCount,
    ] = await Promise.all([
      Expense.getCategoryBreakdown(req.user._id, startDate && endDate ? { startDate, endDate } : null),
      Expense.getPaymentMethodBreakdown(req.user._id, startDate && endDate ? { startDate, endDate } : null),
      Expense.getTotalSpent(req.user._id, startDate || null, endDate || null),
      Expense.aggregate([
        { $match: query },
        { $group: { _id: null, avg: { $avg: '$amount' } } },
      ]),
      Expense.findOne(query).sort({ amount: -1 }),
      Expense.countDocuments(query),
    ]);

    logger.info('GetStatistics: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      statistics: {
        totalSpent: parseFloat(totalSpent.toFixed(2)),
        averageExpense: averageExpense[0]?.avg ? parseFloat(averageExpense[0].avg.toFixed(2)) : 0,
        highestExpense: highestExpense ? parseFloat(highestExpense.amount.toFixed(2)) : 0,
        expenseCount,
        categoryBreakdown,
        paymentMethodBreakdown,
      },
    });
  } catch (error) {
    logger.error('GetStatistics error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve statistics',
    });
  }
};

/**
 * @desc    Export expenses
 * @route   GET /api/expenses/export
 * @access  Private
 */
exports.exportExpenses = async (req, res) => {
  try {
    const { format = 'json', startDate, endDate } = req.query;

    logger.info('ExportExpenses: Request received', { userId: req.user._id, format });

    const query = { user: req.user._id, deletedAt: null };

    if (startDate && endDate) {
      query.date = {
        $gte: new Date(startDate),
        $lte: new Date(endDate),
      };
    }

    const expenses = await Expense.find(query).sort({ date: -1 }).lean();

    if (format === 'csv') {
      const csv = [
        'Title,Amount,Category,Date,Payment Method,Vendor,Notes',
        ...expenses.map(
          e =>
            `"${e.title}",${e.amount},"${e.category}","${new Date(e.date).toLocaleDateString()}","${e.paymentMethod}","${e.vendor || ''}","${e.notes || ''}"`
        ),
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="expenses.csv"');
      return res.send(csv);
    }

    res.json({
      success: true,
      expenses: expenses.map(buildExpenseResponse),
    });
  } catch (error) {
    logger.error('ExportExpenses error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Export failed',
    });
  }
};

// ============= CREATE CONTROLLER =============

/**
 * @desc    Create new expense
 * @route   POST /api/expenses
 * @access  Private
 */
exports.createExpense = async (req, res) => {
  try {
    const {
      title,
      amount,
      category,
      date,
      description,
      paymentMethod,
      vendor,
      tags,
      notes,
      isRecurring,
      isBillPayment,
    } = req.body;

    logger.info('CreateExpense: Request received', { userId: req.user._id });

    const expenseData = {
      user: req.user._id,
      title: title.trim(),
      amount,
      category,
      date: date || new Date(),
      description,
      paymentMethod: paymentMethod || 'cash',
      vendor,
      tags: tags || [],
      notes,
      isRecurring: isRecurring || false,
      isBillPayment: isBillPayment || false,
    };

    const expense = await Expense.create(expenseData);

    logger.info('CreateExpense: Created successfully', { expenseId: expense._id });

    res.status(201).json({
      success: true,
      message: 'Expense created successfully',
      expense: buildExpenseResponse(expense),
    });
  } catch (error) {
    logger.error('CreateExpense error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to create expense',
    });
  }
};

// ============= UPDATE CONTROLLER =============

/**
 * @desc    Update expense
 * @route   PUT /api/expenses/:id
 * @access  Private
 */
exports.updateExpense = async (req, res) => {
  try {
    let expense = await Expense.findById(req.params.id);

    if (!expense) {
      logger.warn('UpdateExpense: Expense not found', { expenseId: req.params.id });
      return res.status(404).json({
        success: false,
        message: 'Expense not found',
      });
    }

    if (expense.user.toString() !== req.user._id.toString()) {
      logger.warn('UpdateExpense: Unauthorized', { expenseId: req.params.id });
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('UpdateExpense: Update attempt', { expenseId: expense._id });

    // Update fields
    const allowedFields = [
      'title',
      'amount',
      'category',
      'date',
      'description',
      'paymentMethod',
      'vendor',
      'tags',
      'notes',
      'isRecurring',
      'isBillPayment',
    ];

    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        expense[field] = req.body[field];
      }
    }

    expense = await expense.save();

    logger.info('UpdateExpense: Updated successfully', { expenseId: expense._id });

    res.json({
      success: true,
      message: 'Expense updated successfully',
      expense: buildExpenseResponse(expense),
    });
  } catch (error) {
    logger.error('UpdateExpense error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to update expense',
    });
  }
};

// ============= DELETE CONTROLLER =============

/**
 * @desc    Delete expense (soft delete)
 * @route   DELETE /api/expenses/:id
 * @access  Private
 */
exports.deleteExpense = async (req, res) => {
  try {
    const expense = await Expense.findById(req.params.id);

    if (!expense) {
      logger.warn('DeleteExpense: Expense not found', { expenseId: req.params.id });
      return res.status(404).json({
        success: false,
        message: 'Expense not found',
      });
    }

    if (expense.user.toString() !== req.user._id.toString()) {
      logger.warn('DeleteExpense: Unauthorized', { expenseId: req.params.id });
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('DeleteExpense: Delete attempt', { expenseId: expense._id });

    await Expense.findByIdAndDelete(req.params.id);

    logger.info('DeleteExpense: Deleted successfully', { expenseId: req.params.id });

    res.json({
      success: true,
      message: 'Expense deleted successfully',
    });
  } catch (error) {
    logger.error('DeleteExpense error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to delete expense',
    });
  }
};

// ============= BULK & SPECIAL OPERATIONS =============

/**
 * @desc    Bulk delete expenses
 * @route   DELETE /api/expenses/bulk/delete
 * @access  Private
 */
exports.bulkDeleteExpenses = async (req, res) => {
  try {
    const { expenseIds } = req.body;

    logger.info('BulkDeleteExpenses: Request received', { userId: req.user._id, count: expenseIds.length });

    await Expense.deleteMany({
      _id: { $in: expenseIds },
      user: req.user._id,
    });

    logger.info('BulkDeleteExpenses: Deleted successfully', { count: expenseIds.length });

    res.json({
      success: true,
      message: `${expenseIds.length} expenses deleted successfully`,
    });
  } catch (error) {
    logger.error('BulkDeleteExpenses error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Bulk delete failed',
    });
  }
};

/**
 * @desc    Mark for reimbursement
 * @route   POST /api/expenses/:id/mark-reimbursable
 * @access  Private
 */
exports.markForReimbursement = async (req, res) => {
  try {
    const expense = await Expense.findById(req.params.id);

    if (!expense) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found',
      });
    }

    if (expense.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    await expense.markForReimbursement();

    logger.info('MarkForReimbursement: Marked successfully', { expenseId: expense._id });

    res.json({
      success: true,
      message: 'Expense marked for reimbursement',
      expense: buildExpenseResponse(expense),
    });
  } catch (error) {
    logger.error('MarkForReimbursement error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to mark for reimbursement',
    });
  }
};

/**
 * @desc    Update reimbursement status
 * @route   PATCH /api/expenses/:id/reimbursement-status
 * @access  Private
 */
exports.updateReimbursementStatus = async (req, res) => {
  try {
    const { status } = req.body;

    const expense = await Expense.findById(req.params.id);

    if (!expense) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found',
      });
    }

    if (expense.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    await expense.updateReimbursementStatus(status, req.user._id);

    logger.info('UpdateReimbursementStatus: Updated successfully', { expenseId: expense._id });

    res.json({
      success: true,
      message: 'Reimbursement status updated',
      expense: buildExpenseResponse(expense),
    });
  } catch (error) {
    logger.error('UpdateReimbursementStatus error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to update status',
    });
  }
};

/**
 * @desc    Bulk update reimbursement status
 * @route   PATCH /api/expenses/bulk/reimbursement-status
 * @access  Private
 */
exports.bulkUpdateReimbursement = async (req, res) => {
  try {
    const { expenseIds, status } = req.body;

    logger.info('BulkUpdateReimbursement: Request received', {
      userId: req.user._id,
      count: expenseIds.length,
    });

    await Expense.updateMany(
      {
        _id: { $in: expenseIds },
        user: req.user._id,
      },
      {
        reimbursementStatus: status,
        updatedBy: req.user._id,
      }
    );

    logger.info('BulkUpdateReimbursement: Updated successfully', { count: expenseIds.length });

    res.json({
      success: true,
      message: `${expenseIds.length} expenses updated`,
    });
  } catch (error) {
    logger.error('BulkUpdateReimbursement error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Bulk update failed',
    });
  }
};

/**
 * @desc    Link expense to reminder
 * @route   POST /api/expenses/:id/link-reminder
 * @access  Private
 */
exports.linkToReminder = async (req, res) => {
  try {
    const { reminderId } = req.body;

    const expense = await Expense.findById(req.params.id);

    if (!expense) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found',
      });
    }

    if (expense.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    await expense.linkToReminder(reminderId);

    logger.info('LinkToReminder: Linked successfully', { expenseId: expense._id });

    res.json({
      success: true,
      message: 'Expense linked to reminder',
      expense: buildExpenseResponse(expense),
    });
  } catch (error) {
    logger.error('LinkToReminder error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to link reminder',
    });
  }
};
