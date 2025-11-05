// config/db.js
const mongoose = require('mongoose');

/**
 * Connect to MongoDB with retries and sane defaults for Mongoose v6+.
 *
 * Expects process.env.MONGODB_URI to contain the full connection string.
 */
const connectDB = async () => {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error('MONGODB_URI environment variable is not set');
  }

  // Mongoose v6+ automatically enables new URL parser and unified topology.
  const opts = {
    // Socket/network options
    socketTimeoutMS: 45000,
    serverSelectionTimeoutMS: 5000,
    // Connection pool
    maxPoolSize: 10,
    // KeepAlive
    keepAlive: true,
    // family: 4 forces IPv4; remove if you need IPv6
    family: 4,
  };

  const maxAttempts = 5;
  let attempt = 0;

  while (attempt < maxAttempts) {
    try {
      attempt++;
      const conn = await mongoose.connect(uri, opts);
      console.log(`✅ MongoDB Connected (${conn.connection.host})`);
      // Optional: set mongoose debug based on env
      if (process.env.NODE_ENV !== 'production') {
        mongoose.set('debug', true);
      }
      // Log connection events
      mongoose.connection.on('connected', () => {
        console.log('Mongoose connected to DB');
      });
      mongoose.connection.on('reconnected', () => {
        console.log('Mongoose reconnected to DB');
      });
      mongoose.connection.on('error', (err) => {
        console.error('Mongoose connection error:', err);
      });
      mongoose.connection.on('disconnected', () => {
        console.warn('Mongoose disconnected');
      });

      return conn;
    } catch (err) {
      console.error(`MongoDB connection attempt ${attempt} failed: ${err.message || err}`);
      if (attempt >= maxAttempts) {
        console.error('Exceeded max MongoDB connection attempts. Exiting.');
        throw err;
      }
      // exponential backoff: 500ms * 2^(attempt-1)
      const backoff = 500 * Math.pow(2, attempt - 1);
      console.log(`Retrying MongoDB connection in ${backoff}ms...`);
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, backoff));
    }
  }
};

module.exports = connectDB;
