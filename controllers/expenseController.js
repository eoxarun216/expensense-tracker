const Expense = require('../models/Expense');

// Get all expenses for user
exports.getExpenses = async (req, res) => {
  try {
    const expenses = await Expense.find({ user: req.user._id })
      .sort({ date: -1 });

    res.json({
      success: true,
      count: expenses.length,
      expenses,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// Get single expense
exports.getExpense = async (req, res) => {
  try {
    const expense = await Expense.findById(req.params.id);
    if (!expense)
      return res.status(404).json({ success: false, message: 'Expense not found' });

    if (expense.user.toString() !== req.user._id.toString())
      return res.status(401).json({ success: false, message: 'Not authorized' });

    res.json({ success: true, expense });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Create expense, optionally with reminderId
exports.createExpense = async (req, res) => {
  try {
    const { title, amount, category, description, date, reminderId } = req.body;

    if (!title || !amount || !category)
      return res.status(400).json({
        success: false,
        message: 'Please provide title, amount, and category',
      });

    const expense = await Expense.create({
      user: req.user._id,
      title,
      amount,
      category,
      description: description || '',
      date: date || Date.now(),
      reminderId: reminderId || null,
    });

    res.status(201).json({ success: true, expense });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Update expense (optionally with reminderId update)
exports.updateExpense = async (req, res) => {
  try {
    let expense = await Expense.findById(req.params.id);
    if (!expense)
      return res.status(404).json({ success: false, message: 'Expense not found' });

    if (expense.user.toString() !== req.user._id.toString())
      return res.status(401).json({ success: false, message: 'Not authorized' });

    // Only allow updating reminderId if provided
    if (req.body.reminderId)
      req.body.reminderId = req.body.reminderId;
    else
      delete req.body.reminderId;

    expense = await Expense.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );

    res.json({ success: true, expense });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Delete expense
exports.deleteExpense = async (req, res) => {
  try {
    const expense = await Expense.findById(req.params.id);
    if (!expense)
      return res.status(404).json({ success: false, message: 'Expense not found' });

    if (expense.user.toString() !== req.user._id.toString())
      return res.status(401).json({ success: false, message: 'Not authorized' });

    await expense.deleteOne();

    res.json({ success: true, message: 'Expense removed' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Statistics endpoint (unchanged)
exports.getStatistics = async (req, res) => {
  try {
    const expenses = await Expense.find({ user: req.user._id });

    const total = expenses.reduce((sum, expense) => sum + expense.amount, 0);

    const categoryTotals = {};
    expenses.forEach((expense) => {
      if (categoryTotals[expense.category]) {
        categoryTotals[expense.category] += expense.amount;
      } else {
        categoryTotals[expense.category] = expense.amount;
      }
    });

    const monthlyTotals = {};
    expenses.forEach((expense) => {
      const month = new Date(expense.date).toISOString().slice(0, 7);
      if (monthlyTotals[month]) {
        monthlyTotals[month] += expense.amount;
      } else {
        monthlyTotals[month] = expense.amount;
      }
    });

    res.json({
      success: true,
      statistics: {
        total,
        count: expenses.length,
        categoryTotals,
        monthlyTotals,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
