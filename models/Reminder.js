const mongoose = require('mongoose');

const reminderSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  // Optional: direct link to an expense created from this reminder (for full sync)
  expenseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Expense',
    default: null,
  },
  title: {
    type: String,
    required: true,
    trim: true,
  },
  type: {
    type: String,
    enum: [
      'EMI', 'Mobile Recharge', 'TV Recharge', 'Utility Bill',
      'Credit Card', 'Insurance', 'Rent', 'Custom'
    ],
    required: true,
  },
  amount: {
    type: Number,
    required: true,
    min: [0, 'Amount must be positive'],
  },
  dueDate: {
    type: Date,
    required: true,
  },
  frequency: {
    type: String,
    enum: ['One-time', 'Monthly', 'Quarterly', 'Yearly', 'Custom'],
    default: 'Monthly',
  },
  status: {
    type: String,
    enum: ['upcoming', 'due', 'overdue', 'paid'],
    default: 'upcoming',
  },
  remindDaysBefore: {
    type: Number,
    default: 2,
    min: 0,
    max: 30,
  },
  notes: {
    type: String,
    trim: true,
    default: '',
  },
  paymentLink: {
    type: String,
    trim: true,
    default: '',
  },
  icon: {
    type: String,
    trim: true,
    default: '',
  }
}, {
  timestamps: true // auto adds createdAt and updatedAt
});

// Optional: Indexes for faster queries
reminderSchema.index({ userId: 1, dueDate: 1 });
reminderSchema.index({ userId: 1, status: 1 });
reminderSchema.index({ expenseId: 1 }); // for reverse linking

module.exports = mongoose.model('Reminder', reminderSchema);
