const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ==================== CONFIGURATION ====================
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

// ==================== MONGODB CONNECTION ====================
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB Atlas');
    console.log('🚀 Database: expense_tracker');
    console.log('📊 Ready for operations');
  })
  .catch((err) => {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  });

// ==================== MONGOOSE SCHEMAS ====================

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Category Schema
const categorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  icon: { type: String, default: '📦' },
  color: { type: String, default: '#A29BFE' },
  createdAt: { type: Date, default: Date.now }
});

categorySchema.index({ userId: 1, name: 1 });

const Category = mongoose.model('Category', categorySchema);

// Expense Schema
const expenseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  amount: { type: Number, required: true },
  categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
  date: { type: Date, required: true },
  description: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

expenseSchema.index({ userId: 1, date: -1 });
expenseSchema.index({ userId: 1, categoryId: 1 });

const Expense = mongoose.model('Expense', expenseSchema);

// ==================== AUTHENTICATION MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Access token required' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid or expired token' 
      });
    }
    req.user = user;
    next();
  });
};

// ==================== ROOT & HEALTH CHECK ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '💰 Expense Tracker API with MongoDB',
    version: '2.0.0',
    database: 'MongoDB Atlas',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: {
        register: 'POST /api/auth/register',
        login: 'POST /api/auth/login',
        me: 'GET /api/auth/me'
      },
      data: {
        categories: 'GET /api/categories',
        expenses: 'GET /api/expenses',
        statistics: 'GET /api/statistics'
      }
    }
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Server is healthy',
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    timestamp: new Date().toISOString()
  });
});

// ==================== AUTHENTICATION ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Name, email, and password are required'
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      message: 'Password must be at least 6 characters'
    });
  }

  try {
    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await User.create({
      name,
      email: email.toLowerCase(),
      password: hashedPassword
    });

    // Create default categories
    const defaultCategories = [
      { userId: user._id, name: 'Food', icon: '🍔', color: '#FF6B6B' },
      { userId: user._id, name: 'Transport', icon: '🚗', color: '#4ECDC4' },
      { userId: user._id, name: 'Shopping', icon: '🛍️', color: '#45B7D1' },
      { userId: user._id, name: 'Entertainment', icon: '🎬', color: '#96CEB4' },
      { userId: user._id, name: 'Bills', icon: '💡', color: '#FFEAA7' },
      { userId: user._id, name: 'Health', icon: '💊', color: '#DFE6E9' },
      { userId: user._id, name: 'Education', icon: '📚', color: '#74B9FF' },
      { userId: user._id, name: 'Others', icon: '📦', color: '#A29BFE' }
    ];

    await Category.insertMany(defaultCategories);

    // Generate token
    const token = jwt.sign(
      { id: user._id.toString(), email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      message: 'User registered successfully',
      data: {
        token,
        user: {
          id: user._id.toString(),
          name: user.name,
          email: user.email
        }
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Error registering user',
      error: error.message
    });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required'
    });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Generate token
    const token = jwt.sign(
      { id: user._id.toString(), email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          id: user._id.toString(),
          name: user.name,
          email: user.email
        }
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Error logging in',
      error: error.message
    });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        created_at: user.createdAt
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user',
      error: error.message
    });
  }
});

// ==================== PROTECTED ROUTES ====================

// Get all categories
app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const categories = await Category.find({ userId: req.user.id }).sort({ name: 1 });

    const formattedCategories = categories.map(cat => ({
      id: cat._id.toString(),
      user_id: cat.userId.toString(),
      name: cat.name,
      icon: cat.icon,
      color: cat.color,
      created_at: cat.createdAt
    }));

    res.json({ 
      success: true, 
      data: formattedCategories,
      count: formattedCategories.length 
    });
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching categories',
      error: error.message
    });
  }
});

// Add new category
app.post('/api/categories', authenticateToken, async (req, res) => {
  const { name, icon, color } = req.body;

  if (!name) {
    return res.status(400).json({
      success: false,
      message: 'Category name is required'
    });
  }

  try {
    const category = await Category.create({
      userId: req.user.id,
      name,
      icon: icon || '📦',
      color: color || '#A29BFE'
    });

    res.json({
      success: true,
      data: {
        id: category._id.toString(),
        user_id: category.userId.toString(),
        name: category.name,
        icon: category.icon,
        color: category.color
      },
      message: 'Category added successfully'
    });
  } catch (error) {
    console.error('Error adding category:', error);
    res.status(500).json({
      success: false,
      message: 'Error adding category',
      error: error.message
    });
  }
});

// Get all expenses
app.get('/api/expenses', authenticateToken, async (req, res) => {
  const { startDate, endDate, categoryId, limit } = req.query;

  try {
    let query = { userId: req.user.id };

    if (startDate) {
      query.date = { ...query.date, $gte: new Date(startDate) };
    }
    if (endDate) {
      query.date = { ...query.date, $lte: new Date(endDate) };
    }
    if (categoryId) {
      query.categoryId = categoryId;
    }

    let expensesQuery = Expense.find(query)
      .sort({ date: -1, createdAt: -1 })
      .populate('categoryId', 'name icon color');

    if (limit) {
      expensesQuery = expensesQuery.limit(parseInt(limit));
    }

    const expenses = await expensesQuery;

    const formattedExpenses = expenses.map(exp => ({
      id: exp._id.toString(),
      title: exp.title,
      amount: exp.amount,
      category_id: exp.categoryId?._id?.toString() || null,
      category_name: exp.categoryId?.name || null,
      category_icon: exp.categoryId?.icon || null,
      category_color: exp.categoryId?.color || null,
      date: exp.date.toISOString().split('T')[0],
      description: exp.description,
      created_at: exp.createdAt,
      updated_at: exp.updatedAt
    }));

    res.json({ 
      success: true, 
      data: formattedExpenses,
      count: formattedExpenses.length 
    });
  } catch (error) {
    console.error('Error fetching expenses:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching expenses',
      error: error.message
    });
  }
});

// Add expense
app.post('/api/expenses', authenticateToken, async (req, res) => {
  const { title, amount, category_id, date, description } = req.body;

  if (!title || !amount || !date) {
    return res.status(400).json({
      success: false,
      message: 'Title, amount, and date are required'
    });
  }

  try {
    const expense = await Expense.create({
      userId: req.user.id,
      title,
      amount: parseFloat(amount),
      categoryId: category_id || null,
      date: new Date(date),
      description: description || ''
    });

    res.json({
      success: true,
      data: {
        id: expense._id.toString(),
        user_id: expense.userId.toString(),
        title: expense.title,
        amount: expense.amount,
        category_id: expense.categoryId?.toString() || null,
        date: expense.date.toISOString().split('T')[0],
        description: expense.description
      },
      message: 'Expense added successfully'
    });
  } catch (error) {
    console.error('Error adding expense:', error);
    res.status(500).json({
      success: false,
      message: 'Error adding expense',
      error: error.message
    });
  }
});

// Update expense
app.put('/api/expenses/:id', authenticateToken, async (req, res) => {
  const { title, amount, category_id, date, description } = req.body;

  try {
    const expense = await Expense.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      {
        title,
        amount: parseFloat(amount),
        categoryId: category_id || null,
        date: new Date(date),
        description: description || '',
        updatedAt: new Date()
      },
      { new: true }
    );

    if (!expense) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found or unauthorized'
      });
    }

    res.json({ 
      success: true, 
      message: 'Expense updated successfully' 
    });
  } catch (error) {
    console.error('Error updating expense:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating expense',
      error: error.message
    });
  }
});

// Delete expense
app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const expense = await Expense.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.id
    });

    if (!expense) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found or unauthorized'
      });
    }

    res.json({ 
      success: true, 
      message: 'Expense deleted successfully' 
    });
  } catch (error) {
    console.error('Error deleting expense:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting expense',
      error: error.message
    });
  }
});

// Get statistics
app.get('/api/statistics', authenticateToken, async (req, res) => {
  const { startDate, endDate } = req.query;

  try {
    let dateQuery = { userId: req.user.id };

    if (startDate) {
      dateQuery.date = { ...dateQuery.date, $gte: new Date(startDate) };
    }
    if (endDate) {
      dateQuery.date = { ...dateQuery.date, $lte: new Date(endDate) };
    }

    // Total expenses
    const totalResult = await Expense.aggregate([
      { $match: dateQuery },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' },
          count: { $sum: 1 }
        }
      }
    ]);

    const total = totalResult.length > 0 ? totalResult[0].total : 0;
    const count = totalResult.length > 0 ? totalResult[0].count : 0;

    // Category breakdown
    const categoryBreakdown = await Expense.aggregate([
      { $match: dateQuery },
      {
        $group: {
          _id: '$categoryId',
          total: { $sum: '$amount' },
          count: { $sum: 1 }
        }
      },
      {
        $lookup: {
          from: 'categories',
          localField: '_id',
          foreignField: '_id',
          as: 'category'
        }
      },
      { $unwind: { path: '$category', preserveNullAndEmptyArrays: true } },
      {
        $project: {
          id: '$category._id',
          name: { $ifNull: ['$category.name', 'Uncategorized'] },
          icon: { $ifNull: ['$category.icon', '📦'] },
          color: { $ifNull: ['$category.color', '#A29BFE'] },
          total: 1,
          count: 1,
          percentage: {
            $cond: [
              { $gt: [total, 0] },
              { $multiply: [{ $divide: ['$total', total] }, 100] },
              0
            ]
          }
        }
      },
      { $sort: { total: -1 } }
    ]);

    res.json({
      success: true,
      data: {
        total: parseFloat(total.toFixed(2)),
        count,
        categoryBreakdown: categoryBreakdown.map(cat => ({
          id: cat.id?.toString() || null,
          name: cat.name,
          icon: cat.icon,
          color: cat.color,
          total: parseFloat(cat.total.toFixed(2)),
          count: cat.count,
          percentage: cat.percentage.toFixed(1)
        }))
      }
    });
  } catch (error) {
    console.error('Error fetching statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching statistics',
      error: error.message
    });
  }
});

// ==================== ERROR HANDLERS ====================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    path: req.path
  });
});

app.use((err, req, res, next) => {
  console.error('Global error:', err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!',
    error: err.message
  });
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
  console.log(`\n🚀 Server running on port ${PORT}`);
  console.log(`📍 Local: http://localhost:${PORT}`);
  console.log(`📍 Health: http://localhost:${PORT}/api/health\n`);
});
