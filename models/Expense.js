const mongoose = require('mongoose');

const ExpenseSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  // Link to Reminder (for payment sync)
  reminderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Reminder',
    default: null,
  },
  title: {
    type: String,
    required: [true, 'Please provide a title'],
    trim: true,
  },
  amount: {
    type: Number,
    required: [true, 'Please provide an amount'],
    min: [0, 'Amount must be positive'],
  },
  category: {
    type: String,
    required: [true, 'Please provide a category'],
    enum: [
      // Housing & Utilities
      'Rent/Mortgage',
      'Electricity',
      'Water',
      'Gas',
      'Internet',
      'Maintenance',
      'Property Tax',

      // Transportation
      'Fuel',
      'Vehicle Maintenance',
      'Vehicle Insurance',
      'Parking',
      'Public Transport',
      'Taxi/Ride',
      'Vehicle Loan',

      // Food & Dining
      'Groceries',
      'Restaurants',
      'Snacks',
      'Coffee/Beverages',
      'Food Delivery',

      // Shopping
      'Clothing',
      'Accessories',
      'Electronics',
      'Home Decor',
      'Online Shopping',

      // Health & Fitness
      'Medical',
      'Medicines',
      'Gym/Fitness',
      'Health Insurance',
      'Wellness/Spa',

      // Education
      'School/College Fees',
      'Books',
      'Online Courses',
      'Coaching',

      // Bills & Subscriptions
      'Mobile Recharge',
      'Streaming Services',
      'Software Subscriptions',
      'Cloud Storage',

      // Work/Business
      'Office Rent',
      'Business Supplies',
      'Work Travel',
      'Tools/Software',
      'Contractors',

      // Finance
      'Loan Payments',
      'Credit Card Bills',
      'Investments',
      'Insurance',
      'Savings',

      // Personal & Family
      'Child Care',
      'Elder Care',
      'Gifts',
      'Donations',
      'Events',

      // Travel & Leisure
      'Flights/Trains',
      'Hotels',
      'Tours/Activities',
      'Entertainment',

      // Others
      'Pet Care',
      'Emergency',
      'Miscellaneous',
    ],
    default: 'Miscellaneous',
  },
  description: {
    type: String,
    trim: true,
    default: '',
  },
  date: {
    type: Date,
    required: true,
    default: Date.now,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  }
}, {
  timestamps: true // auto-manage createdAt, updatedAt fields
});

// Index for faster user/date/category queries
ExpenseSchema.index({ user: 1, date: -1 });
ExpenseSchema.index({ user: 1, category: 1 });
ExpenseSchema.index({ reminderId: 1 }); // for reminder-expense join

module.exports = mongoose.model('Expense', ExpenseSchema);
