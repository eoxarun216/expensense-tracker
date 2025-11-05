// config/db.js
const mongoose = require('mongoose');

const connectDB = async () => {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error('MONGODB_URI environment variable is not set');
  }

  // Mongoose v6+ handles parser/unified options internally.
  const opts = {
    // connection pool size:
    maxPoolSize: 10,
    // how long to try selecting a server before erroring
    serverSelectionTimeoutMS: 5000,
    // how long to allow sockets to be idle before closing
    socketTimeoutMS: 60000,
    // Optional: if you must restrict to IPv4 enable family:4
    // family: 4,
  };

  const maxAttempts = 5;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const conn = await mongoose.connect(uri, opts);
      if (process.env.NODE_ENV !== 'production') {
        mongoose.set('debug', true);
      }
      // connection event logs
      mongoose.connection.on('connected', () => console.log('Mongoose connected to DB'));
      mongoose.connection.on('reconnected', () => console.log('Mongoose reconnected'));
      mongoose.connection.on('disconnected', () => console.warn('Mongoose disconnected'));
      mongoose.connection.on('error', (err) => console.error('Mongoose connection error:', err));

      console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
      return conn;
    } catch (err) {
      console.error(`MongoDB connection attempt ${attempt} failed: ${err.message || err}`);
      if (attempt === maxAttempts) {
        console.error('Exceeded max MongoDB connection attempts. Exiting.');
        throw err;
      }
      // exponential backoff
      const backoff = 500 * Math.pow(2, attempt - 1);
      console.log(`Retrying MongoDB connection in ${backoff}ms...`);
      await new Promise((r) => setTimeout(r, backoff));
    }
  }
};

module.exports = connectDB;
