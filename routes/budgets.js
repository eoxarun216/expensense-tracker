const express = require('express');
const router = express.Router();
const Budget = require('../models/Budget');
const { protect } = require('../middleware/auth');

// ==================== GET ALL BUDGETS (INCOME + EXPENSES) ====================

// Get all budgets for user (includes both income and expenses)
router.get('/', protect, async (req, res) => {
  try {
    const { type, period, incomeSource } = req.query;
    
    // Build query
    const query = { userId: req.user.id };
    if (type) query.type = type; // Filter by 'income' or 'expense'
    if (period) query.period = period; // Filter by 'weekly', 'monthly', 'yearly'
    if (incomeSource) query.incomeSource = incomeSource; // Filter by income source
    
    const budgets = await Budget.find(query).sort({ createdAt: -1 });
    
    res.json({ 
      success: true, 
      count: budgets.length,
      budgets 
    });
  } catch (error) {
    console.error('Error fetching budgets:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== GET FINANCIAL SUMMARY ====================

// Get financial summary (income, expenses, net income, etc.)
router.get('/summary', protect, async (req, res) => {
  try {
    const { period } = req.query;
    
    const [
      totalIncome,
      totalExpenses,
      incomeBreakdown,
      expenseBreakdown,
      financialHealth
    ] = await Promise.all([
      Budget.getTotalIncome(req.user.id, period),
      Budget.getTotalExpenses(req.user.id, period),
      Budget.getIncomeBreakdown(req.user.id, period),
      Budget.getExpenseBreakdown(req.user.id, period),
      Budget.getFinancialHealth(req.user.id, period)
    ]);
    
    res.json({
      success: true,
      summary: {
        totalIncome,
        totalExpenses,
        netIncome: totalIncome - totalExpenses,
        savingsRate: totalIncome > 0 ? ((totalIncome - totalExpenses) / totalIncome) * 100 : 0,
        incomeBreakdown,
        expenseBreakdown,
        financialHealth
      }
    });
  } catch (error) {
    console.error('Error fetching summary:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== GET SPECIFIC ENTRIES ====================

// Get all income entries
router.get('/income', protect, async (req, res) => {
  try {
    const { period } = req.query;
    // Note: Filtering happens in JS after fetching from DB
    const incomes = await Budget.getIncomeByUser(req.user.id);
    
    // Filter by period if provided
    const filtered = period 
      ? incomes.filter(income => income.period === period)
      : incomes;
    
    res.json({ 
      success: true, 
      count: filtered.length,
      incomes: filtered 
    });
  } catch (error) {
    console.error('Error fetching income:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get all expense entries (budgets)
router.get('/expenses', protect, async (req, res) => {
  try {
    const { period } = req.query;
    // Note: Filtering happens in JS after fetching from DB
    const expenses = await Budget.getExpensesByUser(req.user.id);
    
    // Filter by period if provided
    const filtered = period 
      ? expenses.filter(expense => expense.period === period)
      : expenses;
    
    res.json({ 
      success: true, 
      count: filtered.length,
      expenses: filtered 
    });
  } catch (error) {
    console.error('Error fetching expenses:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== CREATE BUDGET OR INCOME ====================

// Create budget (expense) or income entry
router.post('/', protect, async (req, res) => {
  try {
    const { category, limit, period, type, incomeSource, incomeAmount } = req.body;
    
    // Validate type if provided
    if (type && !['income', 'expense'].includes(type)) {
      return res.status(400).json({
        success: false,
        message: 'Type must be either "income" or "expense"',
      });
    }

    // Validate required fields based on type
    if (type === 'income') {
      if (!incomeSource || incomeAmount === undefined) {
        return res.status(400).json({
          success: false,
          message: 'Income source and amount are required for income entries',
        });
      }
    } else if (type === 'expense' || !type) { // Default to expense if type is not provided
      if (!limit) {
        return res.status(400).json({
          success: false,
          message: 'Limit is required for expense entries',
        });
      }
    }

    // Check if entry already exists
    const query = {
      userId: req.user.id,
      category,
      period: period || 'monthly',
      type: type || 'expense',
    };
    
    // For income, also check by source
    if (type === 'income') {
      query.incomeSource = incomeSource;
    }
    
    const existingEntry = await Budget.findOne(query);

    if (existingEntry) {
      return res.status(400).json({
        success: false,
        message: `${type === 'income' ? 'Income' : 'Budget'} already exists for this category${type === 'income' ? ' and source' : ''} and period`,
      });
    }

    // Create the budget/income entry
    const budgetData = {
      userId: req.user.id,
      category,
      period: period || 'monthly',
      type: type || 'expense',
    };
    
    // Add type-specific fields
    if (type === 'income') {
      budgetData.incomeSource = incomeSource;
      budgetData.incomeAmount = incomeAmount;
      budgetData.limit = 0;
      budgetData.spent = 0;
    } else {
      budgetData.limit = limit;
      budgetData.spent = 0;
    }

    const budget = new Budget(budgetData);
    await budget.save();
    
    res.status(201).json({ 
      success: true, 
      message: `${type === 'income' ? 'Income' : 'Budget'} created successfully`,
      budget 
    });
  } catch (error) {
    console.error('Error creating budget/income:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== UPDATE BUDGET OR INCOME ====================

// Update budget or income
router.put('/:id', protect, async (req, res) => {
  try {
    const { category, limit, period, incomeSource, incomeAmount, spent } = req.body;

    let budget = await Budget.findById(req.params.id);

    if (!budget) {
      return res.status(404).json({ success: false, message: 'Entry not found' });
    }

    // Check if budget belongs to user
    if (budget.userId.toString() !== req.user.id) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    // Update based on type
    if (budget.type === 'income') {
      // Update income fields
      if (incomeAmount !== undefined) budget.incomeAmount = incomeAmount;
      if (incomeSource) budget.incomeSource = incomeSource;
      if (category) budget.category = category;
      if (period) budget.period = period;
    } else {
      // Update expense fields
      if (limit !== undefined) budget.limit = limit;
      if (spent !== undefined) budget.spent = spent;
      if (category) budget.category = category;
      if (period) budget.period = period;
    }

    await budget.save();
    res.json({ 
      success: true, 
      message: `${budget.type === 'income' ? 'Income' : 'Budget'} updated successfully`,
      budget 
    });
  } catch (error) {
    console.error('Error updating budget/income:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== SPECIALIZED INCOME ROUTES ====================

// Set/Update personal income (convenience endpoint)
router.post('/income/personal', protect, async (req, res) => {
  try {
    const { amount, period } = req.body;

    if (amount === undefined || amount < 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid amount is required',
      });
    }

    // Check if personal income exists
    let income = await Budget.findOne({
      userId: req.user.id,
      type: 'income',
      incomeSource: 'personal',
      period: period || 'monthly',
    });

    if (income) {
      // Update existing
      income.incomeAmount = amount;
      await income.save();
    } else {
      // Create new
      income = new Budget({
        userId: req.user.id,
        category: 'Personal Income',
        type: 'income',
        incomeSource: 'personal',
        incomeAmount: amount,
        period: period || 'monthly',
        limit: 0,
        spent: 0,
      });
      await income.save();
    }

    res.json({
      success: true,
      message: 'Personal income set successfully',
      budget: income,
    });
  } catch (error) {
    console.error('Error setting personal income:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Set/Update family income (convenience endpoint)
router.post('/income/family', protect, async (req, res) => {
  try {
    const { amount, period } = req.body;

    if (amount === undefined || amount < 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid amount is required',
      });
    }

    // Check if family income exists
    let income = await Budget.findOne({
      userId: req.user.id,
      type: 'income',
      incomeSource: 'family',
      period: period || 'monthly',
    });

    if (income) {
      // Update existing
      income.incomeAmount = amount;
      await income.save();
    } else {
      // Create new
      income = new Budget({
        userId: req.user.id,
        category: 'Family Income',
        type: 'income',
        incomeSource: 'family',
        incomeAmount: amount,
        period: period || 'monthly',
        limit: 0,
        spent: 0,
      });
      await income.save();
    }

    res.json({
      success: true,
      message: 'Family income set successfully',
      budget: income,
    });
  } catch (error) {
    console.error('Error setting family income:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== UPDATE SPENT AMOUNT ====================

// Update spent amount for a budget (expense only)
router.patch('/:id/spent', protect, async (req, res) => {
  try {
    const { spent } = req.body;

    if (spent === undefined || spent < 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid spent amount is required',
      });
    }

    const budget = await Budget.findById(req.params.id);

    if (!budget) {
      return res.status(404).json({ success: false, message: 'Budget not found' });
    }

    // Check if budget belongs to user
    if (budget.userId.toString() !== req.user.id) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    // Check if it's an expense entry
    if (budget.type !== 'expense') {
      return res.status(400).json({
        success: false,
        message: 'Can only update spent amount for expense entries',
      });
    }

    budget.spent = spent;
    await budget.save();

    res.json({
      success: true,
      message: 'Spent amount updated successfully',
      budget,
    });
  } catch (error) {
    console.error('Error updating spent amount:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== DELETE BUDGET OR INCOME ====================

// Delete budget or income
router.delete('/:id', protect, async (req, res) => {
  try {
    const budget = await Budget.findById(req.params.id);

    if (!budget) {
      return res.status(404).json({ success: false, message: 'Entry not found' });
    }

    // Check if budget belongs to user
    if (budget.userId.toString() !== req.user.id) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    await Budget.findByIdAndDelete(req.params.id);
    
    res.json({ 
      success: true, 
      message: `${budget.type === 'income' ? 'Income' : 'Budget'} deleted successfully` 
    });
  } catch (error) {
    console.error('Error deleting budget/income:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== ANALYTICS ENDPOINTS ====================

// Get income breakdown by source
router.get('/analytics/income-breakdown', protect, async (req, res) => {
  try {
    const { period } = req.query;
    const breakdown = await Budget.getIncomeBreakdown(req.user.id, period);
    
    res.json({
      success: true,
      breakdown,
    });
  } catch (error) {
    console.error('Error fetching income breakdown:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get expense breakdown by category
router.get('/analytics/expense-breakdown', protect, async (req, res) => {
  try {
    const { period } = req.query;
    const breakdown = await Budget.getExpenseBreakdown(req.user.id, period);
    
    res.json({
      success: true,
      breakdown,
    });
  } catch (error) {
    console.error('Error fetching expense breakdown:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get financial health score
router.get('/analytics/health', protect, async (req, res) => {
  try {
    const { period } = req.query;
    const health = await Budget.getFinancialHealth(req.user.id, period);
    
    res.json({
      success: true,
      health,
    });
  } catch (error) {
    console.error('Error fetching financial health:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;