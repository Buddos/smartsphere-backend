import express from 'express';
import { authMiddleware, requireRole } from '../middleware/authMiddleware.js';

const router = express.Router();

// Protect all admin routes
router.use(authMiddleware);
router.use(requireRole(['admin', 'super_admin']));

// Admin routes
router.get('/stats', (req, res) => {
  res.json({
    status: 'success',
    message: 'Admin stats endpoint',
    data: { users: 150, courses: 45 }
  });
});

// ✅ FIX: Export as default
export default router;