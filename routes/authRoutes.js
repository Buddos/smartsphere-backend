const express = require('express');
const { body } = require('express-validator');
const {
  login,
  register,
  verifyToken,
  logout
} = require('../controllers/authController');
const { authMiddleware } = require('../middleware/authMiddleware');

const router = express.Router();

// ... your route definitions

module.exports = router;