const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Health check endpoint (without database test first)
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: '🎓 Egerton SmartSphere API is running!',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Simple test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'API is working!',
    data: {
      university: 'Egerton University',
      system: 'SmartSphere',
      status: 'Active'
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: '🎓 Egerton SmartSphere Backend API',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      test: '/api/test'
    },
    status: 'Running 🚀'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 SmartSphere API running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV}`);
});
