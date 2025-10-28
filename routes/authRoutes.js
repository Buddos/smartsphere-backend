import express from 'express';
import { body } from 'express-validator';
import {
  login,
  register,
  verifyToken,
  logout
} from '../controllers/authController.js';
import { authMiddleware } from '../middleware/authMiddleware.js';

const router = express.Router();

// Validation rules
const loginValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
];

const registerValidation = [
  body('name').trim().isLength({ min: 2 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('role').isIn(['student', 'lecturer', 'admin', 'security', 'counselor'])
];

// Routes
router.post('/login', loginValidation, login);
router.post('/register', registerValidation, register);
router.get('/verify', authMiddleware, verifyToken);
router.post('/logout', authMiddleware, logout);

export default router;