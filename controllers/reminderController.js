// File: controllers/reminderController.js

const Reminder = require('../models/Reminder');
const logger = require('../utils/logger');

// ============= HELPER FUNCTIONS =============

/**
 * Build reminder response
 */
const buildReminderResponse = (reminder) => ({
  id: reminder._id,
  title: reminder.title,
  type: reminder.type,
  amount: reminder.amount,
  formattedAmount: `₹${reminder.amount.toFixed(2)}`,
  dueDate: reminder.dueDate,
  formattedDueDate: new Date(reminder.dueDate).toLocaleDateString('en-IN'),
  status: reminder.status,
  priority: reminder.priority,
  frequency: reminder.frequency,
  isRecurring: reminder.isRecurring,
  remindDaysBefore: reminder.remindDaysBefore,
  totalPaidAmount: reminder.totalPaidAmount,
  remainingAmount: reminder.remainingAmount,
  isFullyPaid: reminder.isFullyPaid,
  description: reminder.description,
  notes: reminder.notes,
  vendor: reminder.vendor,
  category: reminder.category,
  createdAt: reminder.createdAt,
  updatedAt: reminder.updatedAt,
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
 * @desc    Get all reminders with filters
 * @route   GET /api/reminders
 * @access  Private
 */
exports.getReminders = async (req, res) => {
  try {
    const { type, status, priority, page = 1, limit = 20 } = req.query;

    logger.info('GetReminders: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const query = { userId: req.user._id, deletedAt: null };

    if (type) query.type = type;
    if (status) query.status = status;
    if (priority) query.priority = priority;

    const reminders = await Reminder.find(query)
      .sort({ dueDate: 1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Reminder.countDocuments(query);

    logger.info('GetReminders: Retrieved successfully', { userId: req.user._id, count: reminders.length });

    res.json({
      success: true,
      data: {
        reminders: reminders.map(buildReminderResponse),
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('GetReminders error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve reminders',
    });
  }
};

/**
 * @desc    Get single reminder
 * @route   GET /api/reminders/:id
 * @access  Private
 */
exports.getReminder = async (req, res) => {
  try {
    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      logger.warn('GetReminder: Reminder not found', { reminderId: req.params.id });
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      logger.warn('GetReminder: Unauthorized', { reminderId: req.params.id });
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('GetReminder: Retrieved successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('GetReminder error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve reminder',
    });
  }
};

/**
 * @desc    Get statistics
 * @route   GET /api/reminders/statistics/overview
 * @access  Private
 */
exports.getStatistics = async (req, res) => {
  try {
    logger.info('GetStatistics: Request received', { userId: req.user._id });

    const stats = await Reminder.getStatistics(req.user._id);

    logger.info('GetStatistics: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      summary: stats,
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
 * @desc    Get overdue reminders
 * @route   GET /api/reminders/status/overdue
 * @access  Private
 */
exports.getOverdue = async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;

    logger.info('GetOverdue: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const now = new Date();

    const reminders = await Reminder.find({
      userId: req.user._id,
      dueDate: { $lt: now },
      status: { $ne: 'completed' },
      deletedAt: null,
    })
      .sort({ dueDate: 1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Reminder.countDocuments({
      userId: req.user._id,
      dueDate: { $lt: now },
      status: { $ne: 'completed' },
      deletedAt: null,
    });

    logger.info('GetOverdue: Retrieved successfully', { userId: req.user._id, count: reminders.length });

    res.json({
      success: true,
      data: {
        reminders: reminders.map(buildReminderResponse),
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
};

/**
 * @desc    Get upcoming reminders
 * @route   GET /api/reminders/status/upcoming
 * @access  Private
 */
exports.getUpcoming = async (req, res) => {
  try {
    const { days = 7, page = 1, limit = 20 } = req.query;

    logger.info('GetUpcoming: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const now = new Date();
    const futureDate = new Date(now.getTime() + parseInt(days) * 24 * 60 * 60 * 1000);

    const reminders = await Reminder.find({
      userId: req.user._id,
      dueDate: { $gte: now, $lte: futureDate },
      status: { $ne: 'completed' },
      deletedAt: null,
    })
      .sort({ dueDate: 1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    const total = await Reminder.countDocuments({
      userId: req.user._id,
      dueDate: { $gte: now, $lte: futureDate },
      status: { $ne: 'completed' },
      deletedAt: null,
    });

    logger.info('GetUpcoming: Retrieved successfully', { userId: req.user._id, count: reminders.length });

    res.json({
      success: true,
      data: {
        reminders: reminders.map(buildReminderResponse),
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
};

/**
 * @desc    Get reminders due today
 * @route   GET /api/reminders/status/today
 * @access  Private
 */
exports.getDueToday = async (req, res) => {
  try {
    logger.info('GetDueToday: Request received', { userId: req.user._id });

    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    const reminders = await Reminder.find({
      userId: req.user._id,
      dueDate: { $gte: today, $lt: tomorrow },
      status: { $ne: 'completed' },
      deletedAt: null,
    })
      .sort({ dueDate: 1 })
      .lean();

    logger.info('GetDueToday: Retrieved successfully', { userId: req.user._id, count: reminders.length });

    res.json({
      success: true,
      reminders: reminders.map(buildReminderResponse),
    });
  } catch (error) {
    logger.error('GetDueToday error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve today reminders',
    });
  }
};

/**
 * @desc    Get reminders by type
 * @route   GET /api/reminders/by-type
 * @access  Private
 */
exports.getByType = async (req, res) => {
  try {
    const { type } = req.query;

    logger.info('GetByType: Request received', { userId: req.user._id, type });

    const reminders = await Reminder.find({
      userId: req.user._id,
      type,
      deletedAt: null,
    })
      .sort({ dueDate: 1 })
      .lean();

    logger.info('GetByType: Retrieved successfully', { userId: req.user._id, count: reminders.length });

    res.json({
      success: true,
      reminders: reminders.map(buildReminderResponse),
    });
  } catch (error) {
    logger.error('GetByType error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve reminders',
    });
  }
};

/**
 * @desc    Get reminders by priority
 * @route   GET /api/reminders/by-priority
 * @access  Private
 */
exports.getByPriority = async (req, res) => {
  try {
    const { priority } = req.query;

    logger.info('GetByPriority: Request received', { userId: req.user._id, priority });

    const reminders = await Reminder.find({
      userId: req.user._id,
      priority,
      status: { $ne: 'completed' },
      deletedAt: null,
    })
      .sort({ dueDate: 1 })
      .lean();

    logger.info('GetByPriority: Retrieved successfully', { userId: req.user._id, count: reminders.length });

    res.json({
      success: true,
      reminders: reminders.map(buildReminderResponse),
    });
  } catch (error) {
    logger.error('GetByPriority error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve reminders',
    });
  }
};

/**
 * @desc    Get recurring reminders
 * @route   GET /api/reminders/recurring
 * @access  Private
 */
exports.getRecurring = async (req, res) => {
  try {
    logger.info('GetRecurring: Request received', { userId: req.user._id });

    const reminders = await Reminder.find({
      userId: req.user._id,
      isRecurring: true,
      deletedAt: null,
    })
      .sort({ dueDate: 1 })
      .lean();

    logger.info('GetRecurring: Retrieved successfully', { userId: req.user._id, count: reminders.length });

    res.json({
      success: true,
      reminders: reminders.map(buildReminderResponse),
    });
  } catch (error) {
    logger.error('GetRecurring error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve recurring reminders',
    });
  }
};

/**
 * @desc    Get notification queue
 * @route   GET /api/reminders/notifications/queue
 * @access  Private
 */
exports.getNotificationQueue = async (req, res) => {
  try {
    logger.info('GetNotificationQueue: Request received', { userId: req.user._id });

    const reminders = await Reminder.find({
      userId: req.user._id,
      notificationEnabled: true,
      status: { $ne: 'completed' },
      deletedAt: null,
    })
      .sort({ dueDate: 1 })
      .lean();

    const needNotification = reminders.filter(r => r.shouldNotify);

    logger.info('GetNotificationQueue: Retrieved successfully', {
      userId: req.user._id,
      count: needNotification.length,
    });

    res.json({
      success: true,
      reminders: needNotification.map(buildReminderResponse),
    });
  } catch (error) {
    logger.error('GetNotificationQueue error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve notifications',
    });
  }
};

/**
 * @desc    Search reminders
 * @route   GET /api/reminders/search
 * @access  Private
 */
exports.searchReminders = async (req, res) => {
  try {
    const { q, page = 1, limit = 20 } = req.query;

    logger.info('SearchReminders: Request received', { userId: req.user._id });

    const { skip, limitNum, page: pageNum } = getPagination(page, limit);

    const { results, total } = await Reminder.searchReminders(req.user._id, q, {
      limit: limitNum,
      skip,
    });

    logger.info('SearchReminders: Retrieved successfully', { userId: req.user._id, count: results.length });

    res.json({
      success: true,
      data: {
        reminders: results.map(buildReminderResponse),
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          pages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (error) {
    logger.error('SearchReminders error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Search failed',
    });
  }
};

/**
 * @desc    Export reminders
 * @route   GET /api/reminders/export
 * @access  Private
 */
exports.exportReminders = async (req, res) => {
  try {
    const { format = 'json' } = req.query;

    logger.info('ExportReminders: Request received', { userId: req.user._id, format });

    const reminders = await Reminder.find({
      userId: req.user._id,
      deletedAt: null,
    })
      .sort({ dueDate: 1 })
      .lean();

    if (format === 'csv') {
      const csv = [
        'Title,Type,Amount,Due Date,Status,Priority,Frequency',
        ...reminders.map(
          r =>
            `"${r.title}","${r.type}",${r.amount},"${new Date(r.dueDate).toLocaleDateString()}","${r.status}","${r.priority}","${r.frequency}"`
        ),
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="reminders.csv"');
      return res.send(csv);
    }

    res.json({
      success: true,
      reminders: reminders.map(buildReminderResponse),
    });
  } catch (error) {
    logger.error('ExportReminders error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Export failed',
    });
  }
};

/**
 * @desc    Get payment history
 * @route   GET /api/reminders/payments/history
 * @access  Private
 */
exports.getPaymentHistory = async (req, res) => {
  try {
    logger.info('GetPaymentHistory: Request received', { userId: req.user._id });

    const reminders = await Reminder.find({
      userId: req.user._id,
      status: 'completed',
      deletedAt: null,
    })
      .sort({ lastPaidAt: -1 })
      .lean();

    logger.info('GetPaymentHistory: Retrieved successfully', { userId: req.user._id });

    res.json({
      success: true,
      history: reminders.map(buildReminderResponse),
    });
  } catch (error) {
    logger.error('GetPaymentHistory error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve payment history',
    });
  }
};

/**
 * @desc    Get linked expenses
 * @route   GET /api/reminders/:id/expenses
 * @access  Private
 */
exports.getLinkedExpenses = async (req, res) => {
  try {
    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('GetLinkedExpenses: Retrieved successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      expenseId: reminder.expenseId,
    });
  } catch (error) {
    logger.error('GetLinkedExpenses error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve linked expenses',
    });
  }
};

// ============= CREATE CONTROLLER =============

/**
 * @desc    Create new reminder
 * @route   POST /api/reminders
 * @access  Private
 */
exports.createReminder = async (req, res) => {
  try {
    const {
      title,
      type,
      amount,
      dueDate,
      frequency,
      priority,
      remindDaysBefore,
      description,
      notes,
      category,
      vendor,
    } = req.body;

    logger.info('CreateReminder: Request received', { userId: req.user._id });

    const reminderData = {
      userId: req.user._id,
      title: title.trim(),
      type,
      amount,
      dueDate,
      frequency: frequency || 'Monthly',
      priority: priority || 'medium',
      remindDaysBefore: remindDaysBefore || 2,
      description,
      notes,
      category,
      vendor,
    };

    const reminder = await Reminder.create(reminderData);

    logger.info('CreateReminder: Created successfully', { reminderId: reminder._id });

    res.status(201).json({
      success: true,
      message: 'Reminder created successfully',
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('CreateReminder error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to create reminder',
    });
  }
};

// ============= UPDATE CONTROLLER =============

/**
 * @desc    Update reminder
 * @route   PUT /api/reminders/:id
 * @access  Private
 */
exports.updateReminder = async (req, res) => {
  try {
    let reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      logger.warn('UpdateReminder: Reminder not found', { reminderId: req.params.id });
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      logger.warn('UpdateReminder: Unauthorized', { reminderId: req.params.id });
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('UpdateReminder: Update attempt', { reminderId: reminder._id });

    const allowedFields = [
      'title',
      'amount',
      'dueDate',
      'frequency',
      'status',
      'priority',
      'remindDaysBefore',
      'description',
      'notes',
      'category',
      'vendor',
    ];

    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        reminder[field] = req.body[field];
      }
    }

    reminder = await reminder.save();

    logger.info('UpdateReminder: Updated successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      message: 'Reminder updated successfully',
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('UpdateReminder error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to update reminder',
    });
  }
};

// ============= PAYMENT STATUS CONTROLLERS =============

/**
 * @desc    Mark reminder as paid
 * @route   POST /api/reminders/:id/mark-paid
 * @access  Private
 */
exports.markReminderPaid = async (req, res) => {
  try {
    const { paidAmount, paymentReference, paymentDate } = req.body;

    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('MarkReminderPaid: Mark attempt', { reminderId: reminder._id });

    await reminder.markAsPaid(paidAmount || reminder.amount, req.user._id);

    logger.info('MarkReminderPaid: Marked successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      message: 'Reminder marked as paid',
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('MarkReminderPaid error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to mark as paid',
    });
  }
};

/**
 * @desc    Mark reminder as unpaid
 * @route   POST /api/reminders/:id/mark-unpaid
 * @access  Private
 */
exports.markReminderUnpaid = async (req, res) => {
  try {
    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('MarkReminderUnpaid: Mark attempt', { reminderId: reminder._id });

    await reminder.revertPayment(req.user._id);

    logger.info('MarkReminderUnpaid: Marked successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      message: 'Reminder reverted to unpaid',
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('MarkReminderUnpaid error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to mark as unpaid',
    });
  }
};

/**
 * @desc    Skip reminder
 * @route   POST /api/reminders/:id/skip
 * @access  Private
 */
exports.skipReminder = async (req, res) => {
  try {
    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('SkipReminder: Skip attempt', { reminderId: reminder._id });

    await reminder.skipReminder(req.user._id);

    logger.info('SkipReminder: Skipped successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      message: 'Reminder skipped',
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('SkipReminder error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to skip reminder',
    });
  }
};

/**
 * @desc    Pause reminder
 * @route   POST /api/reminders/:id/pause
 * @access  Private
 */
exports.pauseReminder = async (req, res) => {
  try {
    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('PauseReminder: Pause attempt', { reminderId: reminder._id });

    await reminder.pauseReminder(req.user._id);

    logger.info('PauseReminder: Paused successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      message: 'Reminder paused',
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('PauseReminder error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to pause reminder',
    });
  }
};

/**
 * @desc    Resume reminder
 * @route   POST /api/reminders/:id/resume
 * @access  Private
 */
exports.resumeReminder = async (req, res) => {
  try {
    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('ResumeReminder: Resume attempt', { reminderId: reminder._id });

    await reminder.resumeReminder(req.user._id);

    logger.info('ResumeReminder: Resumed successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      message: 'Reminder resumed',
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('ResumeReminder error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to resume reminder',
    });
  }
};

/**
 * @desc    Mark as notified
 * @route   POST /api/reminders/:id/mark-notified
 * @access  Private
 */
exports.markAsNotified = async (req, res) => {
  try {
    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('MarkAsNotified: Mark attempt', { reminderId: reminder._id });

    await reminder.markAsNotified();

    logger.info('MarkAsNotified: Marked successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      message: 'Marked as notified',
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('MarkAsNotified error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to mark as notified',
    });
  }
};

// ============= LINKING CONTROLLERS =============

/**
 * @desc    Link to expense
 * @route   POST /api/reminders/:id/link-expense
 * @access  Private
 */
exports.linkToExpense = async (req, res) => {
  try {
    const { expenseId } = req.body;

    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('LinkToExpense: Link attempt', { reminderId: reminder._id });

    await reminder.linkToExpense(expenseId, req.user._id);

    logger.info('LinkToExpense: Linked successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      message: 'Expense linked successfully',
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('LinkToExpense error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to link expense',
    });
  }
};

/**
 * @desc    Unlink from expense
 * @route   POST /api/reminders/:id/unlink-expense
 * @access  Private
 */
exports.unlinkFromExpense = async (req, res) => {
  try {
    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('UnlinkFromExpense: Unlink attempt', { reminderId: reminder._id });

    reminder.expenseId = null;
    await reminder.save();

    logger.info('UnlinkFromExpense: Unlinked successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      message: 'Expense unlinked successfully',
      reminder: buildReminderResponse(reminder),
    });
  } catch (error) {
    logger.error('UnlinkFromExpense error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to unlink expense',
    });
  }
};

/**
 * @desc    Calculate next occurrence
 * @route   POST /api/reminders/:id/next-occurrence
 * @access  Private
 */
exports.calculateNextOccurrence = async (req, res) => {
  try {
    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('CalculateNextOccurrence: Calculate attempt', { reminderId: reminder._id });

    const nextDate = reminder.calculateNextDueDate();

    logger.info('CalculateNextOccurrence: Calculated successfully', { reminderId: reminder._id });

    res.json({
      success: true,
      nextDueDate: nextDate,
    });
  } catch (error) {
    logger.error('CalculateNextOccurrence error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to calculate next occurrence',
    });
  }
};

// ============= BULK OPERATIONS =============

/**
 * @desc    Bulk mark as paid
 * @route   POST /api/reminders/bulk/mark-paid
 * @access  Private
 */
exports.bulkMarkPaid = async (req, res) => {
  try {
    const { reminderIds } = req.body;

    logger.info('BulkMarkPaid: Request received', { userId: req.user._id, count: reminderIds.length });

    await Reminder.updateMany(
      {
        _id: { $in: reminderIds },
        userId: req.user._id,
      },
      {
        status: 'completed',
        totalPaidAmount: { $eq: '$amount' },
      }
    );

    logger.info('BulkMarkPaid: Marked successfully', { count: reminderIds.length });

    res.json({
      success: true,
      message: `${reminderIds.length} reminders marked as paid`,
    });
  } catch (error) {
    logger.error('BulkMarkPaid error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Bulk operation failed',
    });
  }
};

/**
 * @desc    Bulk delete reminders
 * @route   DELETE /api/reminders/bulk/delete
 * @access  Private
 */
exports.bulkDeleteReminders = async (req, res) => {
  try {
    const { reminderIds } = req.body;

    logger.info('BulkDeleteReminders: Request received', { userId: req.user._id, count: reminderIds.length });

    await Reminder.deleteMany({
      _id: { $in: reminderIds },
      userId: req.user._id,
    });

    logger.info('BulkDeleteReminders: Deleted successfully', { count: reminderIds.length });

    res.json({
      success: true,
      message: `${reminderIds.length} reminders deleted successfully`,
    });
  } catch (error) {
    logger.error('BulkDeleteReminders error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Bulk delete failed',
    });
  }
};

// ============= DELETE CONTROLLER =============

/**
 * @desc    Delete reminder
 * @route   DELETE /api/reminders/:id
 * @access  Private
 */
exports.deleteReminder = async (req, res) => {
  try {
    const reminder = await Reminder.findById(req.params.id);

    if (!reminder) {
      logger.warn('DeleteReminder: Reminder not found', { reminderId: req.params.id });
      return res.status(404).json({
        success: false,
        message: 'Reminder not found',
      });
    }

    if (reminder.userId.toString() !== req.user._id.toString()) {
      logger.warn('DeleteReminder: Unauthorized', { reminderId: req.params.id });
      return res.status(403).json({
        success: false,
        message: 'Not authorized',
      });
    }

    logger.info('DeleteReminder: Delete attempt', { reminderId: reminder._id });

    await Reminder.findByIdAndDelete(req.params.id);

    logger.info('DeleteReminder: Deleted successfully', { reminderId: req.params.id });

    res.json({
      success: true,
      message: 'Reminder deleted successfully',
    });
  } catch (error) {
    logger.error('DeleteReminder error', { error: error.message });
    res.status(500).json({
      success: false,
      message: 'Failed to delete reminder',
    });
  }
};
