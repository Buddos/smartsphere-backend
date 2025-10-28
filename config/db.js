import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

// Create MySQL connection pool with serverless optimization
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true,
  // Serverless specific optimizations
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

// Test database connection with better error handling
const testConnection = async () => {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Database connected successfully');
    connection.release();
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    
    // Don't exit process in serverless environment
    if (process.env.NODE_ENV === 'production') {
      console.log('⚠️  Continuing without database connection...');
      return false;
    } else {
      process.exit(1);
    }
  }
};

// Initialize database connection
testConnection();

// Handle connection errors gracefully
pool.on('error', (err) => {
  console.error('Database pool error:', err);
});

export default pool;