const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Database connection
const db = require('./database/connection');

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    await db.query('SELECT NOW()');
    
    res.json({ 
      status: 'OK', 
      message: '🎓 Egerton SmartSphere API is running!',
      database: 'Connected to Render PostgreSQL',
      timestamp: new Date().toISOString(),
      version: '1.0.0'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'Error', 
      message: 'Database connection failed',
      error: error.message 
    });
  }
});

// Test users endpoint
app.get('/api/users', async (req, res) => {
  try {
    const result = await db.query('SELECT user_id, full_name, email, school_id FROM users LIMIT 5');
    
    res.json({
      success: true,
      data: result.rows,
      count: result.rowCount
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Create sample user (for testing)
app.post('/api/users/test', async (req, res) => {
  try {
    const result = await db.query(
      `INSERT INTO users (university_id, full_name, email, password_hash, school_id, barcode_value, gender, course_name, faculty_name) 
       VALUES (1, 'Test Student', 'test@students.egerton.ac.ke', 'temp_password', 'EU/CS/2024/999', 'BARCODE-TEST-001', 'Male', 'BSc Computer Science', 'Faculty of Science')
       RETURNING user_id, full_name, email, school_id`
    );
    
    res.json({
      success: true,
      message: 'Test user created successfully',
      user: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: '🎓 Egerton SmartSphere Backend API',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      users: '/api/users',
      create_test_user: '/api/users/test (POST)'
    },
    database: 'PostgreSQL on Render',
    status: 'Running 🚀'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 SmartSphere API running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV}`);
});