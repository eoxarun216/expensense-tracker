const mongoose = require('mongoose');

const reminderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  type: { type: String, enum: [
    'EMI', 'Mobile Recharge', 'TV Recharge', 'Utility Bill', 'Credit Card', 'Insurance', 'Rent', 'Custom'
  ], required: true },
  amount: { type: Number, required: true },
  dueDate: { type: Date, required: true },
  frequency: { type: String, enum: ['One-time', 'Monthly', 'Quarterly', 'Yearly', 'Custom'], default: 'Monthly' },
  status: { type: String, enum: ['upcoming', 'due', 'overdue', 'paid'], default: 'upcoming' },
  remindDaysBefore: { type: Number, default: 2 }, // Days before due to alert
  notes: { type: String },
  paymentLink: { type: String },
  icon: { type: String },
  // timeStamps will auto add createdAt, updatedAt
}, { timestamps: true });

module.exports = mongoose.model('Reminder', reminderSchema);
