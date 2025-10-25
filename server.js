const express = require('express');
const mysql = require('mysql2');
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

// ==================== DATABASE CONFIGURATION ====================
const dbConfig = {
  host: process.env.MYSQLHOST,
  port: parseInt(process.env.MYSQLPORT || '3306'),
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
};

const pool = mysql.createPool(dbConfig);
const promisePool = pool.promise();

// ==================== DATABASE CONNECTION TEST ====================
console.log('🔍 Attempting to connect to MySQL...');
pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ MySQL Connection Error:', err.message);
    return;
  }
  console.log('✅ Connected to Railway MySQL database');
  connection.release();
  initializeDatabase();
});

// ==================== DATABASE INITIALIZATION ====================
async function initializeDatabase() {
  try {
    // Create users table
    await promisePool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email)
      )
    `);
    console.log('✅ Users table ready');

    // Create categories table
    await promisePool.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        name VARCHAR(50) NOT NULL,
        icon VARCHAR(50),
        color VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_category (user_id, name)
      )
    `);
    console.log('✅ Categories table ready');

    // Create expenses table
    await promisePool.query(`
      CREATE TABLE IF NOT EXISTS expenses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        title VARCHAR(100) NOT NULL,
        amount DECIMAL(10, 2) NOT NULL,
        category_id INT,
        date DATE NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL,
        INDEX idx_user_date (user_id, date)
      )
    `);
    console.log('✅ Expenses table ready');

    console.log('✅ Database initialization complete');
  } catch (error) {
    console.error('❌ Database initialization error:', error.message);
  }
}

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
    message: '💰 Expense Tracker API with Authentication',
    version: '2.0.0',
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
    const [existingUsers] = await promisePool.query(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const [result] = await promisePool.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    const userId = result.insertId;

    // Insert default categories for new user
    await promisePool.query(`
      INSERT INTO categories (user_id, name, icon, color) VALUES
      (?, 'Food', '🍔', '#FF6B6B'),
      (?, 'Transport', '🚗', '#4ECDC4'),
      (?, 'Shopping', '🛍️', '#45B7D1'),
      (?, 'Entertainment', '🎬', '#96CEB4'),
      (?, 'Bills', '💡', '#FFEAA7'),
      (?, 'Health', '💊', '#DFE6E9'),
      (?, 'Education', '📚', '#74B9FF'),
      (?, 'Others', '📦', '#A29BFE')
    `, [userId, userId, userId, userId, userId, userId, userId, userId]);

    // Generate token
    const token = jwt.sign(
      { id: userId, email: email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      message: 'User registered successfully',
      data: {
        token,
        user: {
          id: userId,
          name,
          email
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
    const [users] = await promisePool.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const user = users[0];

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
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          id: user.id,
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
    const [users] = await promisePool.query(
      'SELECT id, name, email, created_at FROM users WHERE id = ?',
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: users[0]
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

// Get all categories (protected)
app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const [rows] = await promisePool.query(
      'SELECT * FROM categories WHERE user_id = ? ORDER BY name',
      [req.user.id]
    );
    res.json({ success: true, data: rows, count: rows.length });
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching categories',
      error: error.message
    });
  }
});

// Add new category (protected)
app.post('/api/categories', authenticateToken, async (req, res) => {
  const { name, icon, color } = req.body;

  if (!name) {
    return res.status(400).json({
      success: false,
      message: 'Category name is required'
    });
  }

  try {
    const [result] = await promisePool.query(
      'INSERT INTO categories (user_id, name, icon, color) VALUES (?, ?, ?, ?)',
      [req.user.id, name, icon || '📦', color || '#A29BFE']
    );

    res.json({
      success: true,
      data: {
        id: result.insertId,
        user_id: req.user.id,
        name,
        icon: icon || '📦',
        color: color || '#A29BFE'
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

// Get all expenses (protected)
app.get('/api/expenses', authenticateToken, async (req, res) => {
  const { startDate, endDate, categoryId, limit } = req.query;

  try {
    let query = `
      SELECT 
        e.id,
        e.title,
        e.amount,
        e.category_id,
        e.date,
        e.description,
        e.created_at,
        e.updated_at,
        c.name as category_name,
        c.icon as category_icon,
        c.color as category_color
      FROM expenses e
      LEFT JOIN categories c ON e.category_id = c.id
      WHERE e.user_id = ?
    `;
    const params = [req.user.id];

    if (startDate) {
      query += ' AND e.date >= ?';
      params.push(startDate);
    }
    if (endDate) {
      query += ' AND e.date <= ?';
      params.push(endDate);
    }
    if (categoryId) {
      query += ' AND e.category_id = ?';
      params.push(categoryId);
    }

    query += ' ORDER BY e.date DESC, e.created_at DESC';

    if (limit) {
      query += ' LIMIT ?';
      params.push(parseInt(limit));
    }

    const [rows] = await promisePool.query(query, params);

    res.json({ success: true, data: rows, count: rows.length });
  } catch (error) {
    console.error('Error fetching expenses:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching expenses',
      error: error.message
    });
  }
});

// Add expense (protected)
app.post('/api/expenses', authenticateToken, async (req, res) => {
  const { title, amount, category_id, date, description } = req.body;

  if (!title || !amount || !date) {
    return res.status(400).json({
      success: false,
      message: 'Title, amount, and date are required'
    });
  }

  try {
    const [result] = await promisePool.query(
      'INSERT INTO expenses (user_id, title, amount, category_id, date, description) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, title, parseFloat(amount), category_id || null, date, description || '']
    );

    res.json({
      success: true,
      data: {
        id: result.insertId,
        user_id: req.user.id,
        title,
        amount: parseFloat(amount),
        category_id,
        date,
        description
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

// Update expense (protected)
app.put('/api/expenses/:id', authenticateToken, async (req, res) => {
  const { title, amount, category_id, date, description } = req.body;

  try {
    const [result] = await promisePool.query(
      'UPDATE expenses SET title = ?, amount = ?, category_id = ?, date = ?, description = ? WHERE id = ? AND user_id = ?',
      [title, parseFloat(amount), category_id || null, date, description || '', req.params.id, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found or unauthorized'
      });
    }

    res.json({ success: true, message: 'Expense updated successfully' });
  } catch (error) {
    console.error('Error updating expense:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating expense',
      error: error.message
    });
  }
});

// Delete expense (protected)
app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const [result] = await promisePool.query(
      'DELETE FROM expenses WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found or unauthorized'
      });
    }

    res.json({ success: true, message: 'Expense deleted successfully' });
  } catch (error) {
    console.error('Error deleting expense:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting expense',
      error: error.message
    });
  }
});

// Get statistics (protected)
app.get('/api/statistics', authenticateToken, async (req, res) => {
  const { startDate, endDate } = req.query;

  try {
    let whereClause = 'WHERE user_id = ?';
    const params = [req.user.id];

    if (startDate) {
      whereClause += ' AND date >= ?';
      params.push(startDate);
    }
    if (endDate) {
      whereClause += ' AND date <= ?';
      params.push(endDate);
    }

    const [totalResult] = await promisePool.query(
      `SELECT COALESCE(SUM(amount), 0) as total, COUNT(*) as count FROM expenses ${whereClause}`,
      params
    );

    let categoryQuery = `
      SELECT 
        c.id,
        c.name,
        c.icon,
        c.color,
        COALESCE(SUM(e.amount), 0) as total,
        COUNT(e.id) as count
      FROM categories c
      LEFT JOIN expenses e ON c.id = e.category_id AND e.user_id = ?
    `;
    
    const categoryParams = [req.user.id];

    if (startDate) {
      categoryQuery += ' AND e.date >= ?';
      categoryParams.push(startDate);
    }
    if (endDate) {
      categoryQuery += ' AND e.date <= ?';
      categoryParams.push(endDate);
    }

    categoryQuery += `
      WHERE c.user_id = ?
      GROUP BY c.id, c.name, c.icon, c.color
      HAVING total > 0
      ORDER BY total DESC
    `;
    
    categoryParams.push(req.user.id);

    const [categoryResult] = await promisePool.query(categoryQuery, categoryParams);

    const total = parseFloat(totalResult[0].total);
    const categoryBreakdown = categoryResult.map(cat => ({
      ...cat,
      total: parseFloat(cat.total),
      percentage: total > 0 ? ((parseFloat(cat.total) / total) * 100).toFixed(1) : '0.0'
    }));

    res.json({
      success: true,
      data: {
        total: total,
        count: totalResult[0].count,
        categoryBreakdown: categoryBreakdown
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
