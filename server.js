const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ==================== DATABASE CONNECTION ====================

// Option 1: Using individual credentials
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

// Option 2: Using MYSQL_URL (uncomment if using this method)
// const pool = mysql.createPool(process.env.MYSQL_URL);

const pool = mysql.createPool(dbConfig);
const promisePool = pool.promise();

// Test connection
console.log('🔍 Attempting to connect to MySQL...');
pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ MySQL Connection Error:', err.message);
    console.error('Code:', err.code);
    console.error('
📋 Troubleshooting:');
    console.error('1. Check Railway MySQL credentials in .env');
    console.error('2. Ensure Railway MySQL has public networking enabled');
    console.error('3. Verify host, port, user, password are correct');
    return;
  }
  console.log('✅ Connected to Railway MySQL database');
  connection.release();
  
  // Initialize database tables
  initializeDatabase();
});

// ==================== DATABASE INITIALIZATION ====================
async function initializeDatabase() {
  try {
    // Create categories table
    await promisePool.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE,
        icon VARCHAR(50),
        color VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Categories table ready');

    // Create expenses table
    await promisePool.query(`
      CREATE TABLE IF NOT EXISTS expenses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(100) NOT NULL,
        amount DECIMAL(10, 2) NOT NULL,
        category_id INT,
        date DATE NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
      )
    `);
    console.log('✅ Expenses table ready');

    // Insert default categories if empty
    const [rows] = await promisePool.query('SELECT COUNT(*) as count FROM categories');
    if (rows[0].count === 0) {
      await promisePool.query(`
        INSERT INTO categories (name, icon, color) VALUES
        ('Food', '🍔', '#FF6B6B'),
        ('Transport', '🚗', '#4ECDC4'),
        ('Shopping', '🛍️', '#45B7D1'),
        ('Entertainment', '🎬', '#96CEB4'),
        ('Bills', '💡', '#FFEAA7'),
        ('Health', '💊', '#DFE6E9'),
        ('Education', '📚', '#74B9FF'),
        ('Others', '📦', '#A29BFE')
      `);
      console.log('✅ Default categories inserted');
    }
  } catch (error) {
    console.error('❌ Database initialization error:', error.message);
  }
}

// ==================== ROUTES ====================

// Root & Health Check
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '💰 Expense Tracker API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/api/health',
      categories: '/api/categories',
      expenses: '/api/expenses',
      statistics: '/api/statistics'
    }
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is healthy',
    database: 'connected',
    timestamp: new Date().toISOString()
  });
});

// ==================== CATEGORIES ROUTES ====================

// Get all categories
app.get('/api/categories', async (req, res) => {
  try {
    const [rows] = await promisePool.query(
      'SELECT * FROM categories ORDER BY name'
    );
    res.json({
      success: true,
      data: rows,
      count: rows.length
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
app.post('/api/categories', async (req, res) => {
  const { name, icon, color } = req.body;

  if (!name) {
    return res.status(400).json({
      success: false,
      message: 'Category name is required'
    });
  }

  try {
    const [result] = await promisePool.query(
      'INSERT INTO categories (name, icon, color) VALUES (?, ?, ?)',
      [name, icon || '📦', color || '#A29BFE']
    );

    res.json({
      success: true,
      data: {
        id: result.insertId,
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

// ==================== EXPENSES ROUTES ====================

// Get all expenses (with optional filters)
app.get('/api/expenses', async (req, res) => {
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
      WHERE 1=1
    `;
    const params = [];

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

    res.json({
      success: true,
      data: rows,
      count: rows.length
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

// Get single expense
app.get('/api/expenses/:id', async (req, res) => {
  try {
    const [rows] = await promisePool.query(
      `SELECT 
        e.*,
        c.name as category_name,
        c.icon as category_icon,
        c.color as category_color
       FROM expenses e
       LEFT JOIN categories c ON e.category_id = c.id
       WHERE e.id = ?`,
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found'
      });
    }

    res.json({
      success: true,
      data: rows[0]
    });
  } catch (error) {
    console.error('Error fetching expense:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching expense',
      error: error.message
    });
  }
});

// Add new expense
app.post('/api/expenses', async (req, res) => {
  const { title, amount, category_id, date, description } = req.body;

  // Validation
  if (!title || !amount || !date) {
    return res.status(400).json({
      success: false,
      message: 'Title, amount, and date are required'
    });
  }

  if (isNaN(amount) || parseFloat(amount) <= 0) {
    return res.status(400).json({
      success: false,
      message: 'Amount must be a positive number'
    });
  }

  try {
    const [result] = await promisePool.query(
      'INSERT INTO expenses (title, amount, category_id, date, description) VALUES (?, ?, ?, ?, ?)',
      [title, parseFloat(amount), category_id || null, date, description || '']
    );

    res.json({
      success: true,
      data: {
        id: result.insertId,
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

// Update expense
app.put('/api/expenses/:id', async (req, res) => {
  const { title, amount, category_id, date, description } = req.body;

  if (!title || !amount || !date) {
    return res.status(400).json({
      success: false,
      message: 'Title, amount, and date are required'
    });
  }

  if (isNaN(amount) || parseFloat(amount) <= 0) {
    return res.status(400).json({
      success: false,
      message: 'Amount must be a positive number'
    });
  }

  try {
    const [result] = await promisePool.query(
      'UPDATE expenses SET title = ?, amount = ?, category_id = ?, date = ?, description = ? WHERE id = ?',
      [title, parseFloat(amount), category_id || null, date, description || '', req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found'
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
app.delete('/api/expenses/:id', async (req, res) => {
  try {
    const [result] = await promisePool.query(
      'DELETE FROM expenses WHERE id = ?',
      [req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Expense not found'
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

// ==================== STATISTICS ROUTE ====================

app.get('/api/statistics', async (req, res) => {
  const { startDate, endDate } = req.query;

  try {
    let whereClause = 'WHERE 1=1';
    const params = [];

    if (startDate) {
      whereClause += ' AND date >= ?';
      params.push(startDate);
    }
    if (endDate) {
      whereClause += ' AND date <= ?';
      params.push(endDate);
    }

    // Total amount and count
    const [totalResult] = await promisePool.query(
      `SELECT 
        COALESCE(SUM(amount), 0) as total, 
        COUNT(*) as count 
       FROM expenses ${whereClause}`,
      params
    );

    // Category-wise breakdown
    const [categoryResult] = await promisePool.query(
      `SELECT 
        c.id,
        c.name,
        c.icon,
        c.color,
        COALESCE(SUM(e.amount), 0) as total,
        COUNT(e.id) as count
       FROM categories c
       LEFT JOIN expenses e ON c.id = e.category_id ${whereClause.replace('WHERE 1=1', '')}
       GROUP BY c.id, c.name, c.icon, c.color
       HAVING total > 0
       ORDER BY total DESC`,
      params
    );

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

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    path: req.path
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
🚀 Server running on port ${PORT}`);
  console.log(`📍 Local: http://localhost:${PORT}`);
  console.log(`📍 Health: http://localhost:${PORT}/api/health
`);
});