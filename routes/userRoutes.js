import express from 'express';
import { authMiddleware } from '../middleware/authMiddleware.js';
import { getProfile, updateProfile } from '../controllers/userController.js';

const router = express.Router();

// Protect all routes
router.use(authMiddleware);

// User routes
router.get('/profile', getProfile);
router.put('/profile', updateProfile);

// ✅ FIX: Export as default
export default router;