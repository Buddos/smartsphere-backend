const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
});

// Middleware
app.use(cors());
app.use(express.json());

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ==================== HEALTH & SYSTEM ENDPOINTS ====================
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT NOW()');
    res.json({
      status: 'OK',
      message: '🎓 Egerton SmartSphere API is running!',
      database: 'Connected to PostgreSQL',
      timestamp: new Date().toISOString(),
      version: '2.0.0'
    });
  } catch (error) {
    res.status(500).json({
      status: 'Error',
      message: 'Database connection failed',
      error: error.message
    });
  }
});

app.get('/', (req, res) => {
  res.json({
    message: '🎓 Egerton SmartSphere Backend API',
    version: '2.0.0',
    system: 'Complete Academic Management System',
    endpoints: {
      auth: ['POST /api/auth/login', 'POST /api/auth/register'],
      users: ['GET /api/users', 'GET /api/users/:id', 'PUT /api/users/:id'],
      timetable: ['GET /api/timetable', 'POST /api/timetable/generate'],
      attendance: ['POST /api/attendance/scan', 'GET /api/attendance/:userId'],
      security: ['GET /api/security/alerts', 'POST /api/security/scan'],
      admin: ['GET /api/admin/stats', 'POST /api/admin/users']
    },
    status: 'Running 🚀'
  });
});

// ==================== AUTHENTICATION ENDPOINTS ====================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Find user by email or school_id
    const userResult = await pool.query(
      'SELECT * FROM users WHERE email = $1 OR school_id = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = userResult.rows[0];

    // In production, you should use bcrypt.compare with hashed passwords
    // For demo, we'll use simple comparison
    const validPassword = password === 'demo123'; // Replace with bcrypt.compare in production

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.user_id, 
        email: user.email, 
        schoolId: user.school_id,
        role: 'student' // You should get this from user_roles table
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.user_id,
        full_name: user.full_name,
        email: user.email,
        school_id: user.school_id,
        course_name: user.course_name,
        faculty_name: user.faculty_name
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { full_name, email, password, school_id, course_name, faculty_name, gender } = req.body;

    // Validate required fields
    if (!full_name || !email || !password || !school_id) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT * FROM users WHERE email = $1 OR school_id = $2',
      [email, school_id]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password (in production)
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const result = await pool.query(
      `INSERT INTO users (
        university_id, full_name, email, password_hash, school_id, 
        barcode_value, gender, course_name, faculty_name, card_issue_date, card_expiry_date
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING user_id, full_name, email, school_id, course_name, faculty_name`,
      [
        1, // university_id
        full_name,
        email,
        hashedPassword,
        school_id,
        `BARCODE-${school_id}`, // Generate barcode from school_id
        gender || 'Male',
        course_name || 'General Studies',
        faculty_name || 'General Faculty',
        new Date(), // card_issue_date
        new Date(new Date().getFullYear() + 4, 6, 31) // card_expiry_date (4 years from now)
      ]
    );

    // Assign student role
    await pool.query(
      'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)',
      [result.rows[0].user_id, 7] // 7 = Student role
    );

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: result.rows[0].user_id, 
        email: result.rows[0].email, 
        schoolId: result.rows[0].school_id,
        role: 'student'
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== USER MANAGEMENT ENDPOINTS ====================
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT user_id, full_name, email, school_id, course_name, faculty_name, card_status FROM users LIMIT 50'
    );
    
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

app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.user_id, u.full_name, u.email, u.school_id, u.course_name, u.faculty_name, 
              u.card_status, u.card_issue_date, u.card_expiry_date, u.profile_photo,
              array_agg(r.role_name) as roles
       FROM users u
       LEFT JOIN user_roles ur ON u.user_id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.role_id
       WHERE u.user_id = $1
       GROUP BY u.user_id`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== TIMETABLE ENDPOINTS ====================
app.get('/api/timetable', authenticateToken, async (req, res) => {
  try {
    const { academic_year, semester } = req.query;
    
    let query = `
      SELECT te.entry_id, te.day_of_week, te.start_time, te.end_time,
             u.unit_code, u.unit_name, v.name as venue_name,
             array_agg(ul.full_name) as lecturers
      FROM timetable_entries te
      JOIN units u ON te.unit_id = u.unit_id
      JOIN venues v ON te.venue_id = v.venue_id
      JOIN users ul ON ul.user_id = ANY(te.lecturer_ids)
      JOIN generated_timetables gt ON te.timetable_id = gt.timetable_id
    `;
    
    const params = [];
    
    if (academic_year && semester) {
      query += ' WHERE gt.academic_year = $1 AND gt.semester = $2';
      params.push(academic_year, semester);
    }
    
    query += ' GROUP BY te.entry_id, u.unit_code, u.unit_name, v.name ORDER BY te.day_of_week, te.start_time';
    
    const result = await pool.query(query, params);
    
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

app.get('/api/timetable/student/:studentId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT te.entry_id, te.day_of_week, te.start_time, te.end_time,
              u.unit_code, u.unit_name, v.name as venue_name,
              array_agg(ul.full_name) as lecturers
       FROM timetable_entries te
       JOIN units u ON te.unit_id = u.unit_id
       JOIN venues v ON te.venue_id = v.venue_id
       JOIN users ul ON ul.user_id = ANY(te.lecturer_ids)
       JOIN student_unit_registration sur ON te.unit_id = sur.unit_id
       WHERE sur.user_id = $1 AND sur.status = 'Registered'
       GROUP BY te.entry_id, u.unit_code, u.unit_name, v.name
       ORDER BY te.day_of_week, te.start_time`,
      [req.params.studentId]
    );

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

// ==================== ATTENDANCE ENDPOINTS ====================
app.post('/api/attendance/scan', authenticateToken, async (req, res) => {
  try {
    const { user_id, qr_code, station_id, scan_type } = req.body;

    if (!user_id || !qr_code) {
      return res.status(400).json({ error: 'User ID and QR code required' });
    }

    // Verify QR code (in real implementation, validate against session)
    const sessionResult = await pool.query(
      'SELECT * FROM attendance_sessions WHERE qr_code_value = $1 AND qr_code_expiry > NOW()',
      [qr_code]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired QR code' });
    }

    const session = sessionResult.rows[0];

    // Record attendance
    const attendanceResult = await pool.query(
      `INSERT INTO attendance_records (session_id, user_id, attendance_status, scanned_at)
       VALUES ($1, $2, 'Present', NOW())
       RETURNING record_id`,
      [session.session_id, user_id]
    );

    // Log security scan
    await pool.query(
      `INSERT INTO scan_logs (user_id, station_id, scan_type, scan_time, verified)
       VALUES ($1, $2, $3, NOW(), true)`,
      [user_id, station_id || 1, scan_type || 'Attendance']
    );

    res.json({
      success: true,
      message: 'Attendance recorded successfully',
      attendance: {
        record_id: attendanceResult.rows[0].record_id,
        session_id: session.session_id,
        unit_id: session.unit_id,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    // Handle duplicate attendance
    if (error.code === '23505') { // Unique violation
      return res.status(400).json({ error: 'Attendance already recorded for this session' });
    }
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/attendance/:userId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ar.record_id, ar.attendance_status, ar.scanned_at,
              u.unit_code, u.unit_name, ases.session_date,
              ul.full_name as lecturer_name
       FROM attendance_records ar
       JOIN attendance_sessions ases ON ar.session_id = ases.session_id
       JOIN units u ON ases.unit_id = u.unit_id
       JOIN users ul ON ases.lecturer_id = ul.user_id
       WHERE ar.user_id = $1
       ORDER BY ar.scanned_at DESC
       LIMIT 50`,
      [req.params.userId]
    );

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

// ==================== SECURITY ENDPOINTS ====================
app.post('/api/security/scan', async (req, res) => {
  try {
    const { user_id, station_id, scan_type, barcode_value } = req.body;

    // Verify user by barcode
    const userResult = await pool.query(
      'SELECT * FROM users WHERE barcode_value = $1 AND card_status = $2',
      [barcode_value, 'Active']
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid card or card not active' });
    }

    const user = userResult.rows[0];

    // Log security scan
    const scanResult = await pool.query(
      `INSERT INTO scan_logs (user_id, station_id, scan_type, scan_time, verified)
       VALUES ($1, $2, $3, NOW(), true)
       RETURNING scan_id`,
      [user.user_id, station_id, scan_type]
    );

    // Update student current state
    const newStatus = scan_type === 'Entry' ? 'Inside' : 'Outside';
    await pool.query(
      `INSERT INTO student_current_state (user_id, last_station_id, current_status, last_scan_time)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         last_station_id = $2,
         current_status = $3,
         last_scan_time = NOW()`,
      [user.user_id, station_id, newStatus]
    );

    res.json({
      success: true,
      message: `Scan recorded successfully - ${scan_type}`,
      scan: {
        scan_id: scanResult.rows[0].scan_id,
        user: {
          full_name: user.full_name,
          school_id: user.school_id,
          course_name: user.course_name
        },
        status: newStatus,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/security/alerts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sa.alert_id, sa.alert_type, sa.description, sa.severity, sa.created_at,
              u.full_name, u.school_id, sa.status
       FROM security_alerts sa
       JOIN users u ON sa.user_id = u.user_id
       WHERE sa.status = 'Active'
       ORDER BY sa.created_at DESC
       LIMIT 20`
    );

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

// ==================== ADMIN ENDPOINTS ====================
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  try {
    // Get total counts
    const usersCount = await pool.query('SELECT COUNT(*) FROM users WHERE is_active = true');
    const studentsCount = await pool.query('SELECT COUNT(*) FROM users WHERE is_active = true AND school_id LIKE $1', ['EU/%']);
    const alertsCount = await pool.query('SELECT COUNT(*) FROM security_alerts WHERE status = $1', ['Active']);
    const attendanceCount = await pool.query('SELECT COUNT(*) FROM attendance_records WHERE DATE(scanned_at) = CURRENT_DATE');

    res.json({
      success: true,
      data: {
        total_users: parseInt(usersCount.rows[0].count),
        total_students: parseInt(studentsCount.rows[0].count),
        active_alerts: parseInt(alertsCount.rows[0].count),
        today_attendance: parseInt(attendanceCount.rows[0].count)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== UTILITY ENDPOINTS ====================
app.post('/api/utils/create-test-data', async (req, res) => {
  try {
    // Create test user if doesn't exist
    const testUser = await pool.query(
      `INSERT INTO users (university_id, full_name, email, password_hash, school_id, barcode_value, gender, course_name, faculty_name)
       VALUES (1, 'Test Student', 'test@egerton.ac.ke', 'demo123', 'EU/CS/2024/001', 'BARCODE-TEST-001', 'Male', 'BSc Computer Science', 'Faculty of Science')
       ON CONFLICT (school_id) DO NOTHING
       RETURNING user_id`
    );

    res.json({
      success: true,
      message: 'Test data ready',
      test_credentials: {
        email: 'test@egerton.ac.ke',
        password: 'demo123',
        school_id: 'EU/CS/2024/001'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== ERROR HANDLING ====================
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    available_endpoints: {
      auth: '/api/auth/*',
      users: '/api/users/*',
      timetable: '/api/timetable/*',
      attendance: '/api/attendance/*',
      security: '/api/security/*',
      admin: '/api/admin/*'
    }
  });
});

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : error.message
  });
});

// ==================== START SERVER ====================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SmartSphere API running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV}`);
  console.log(`🗄️ Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
  console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Configured' : 'Not set'}`);
  console.log(`📚 Available at: http://localhost:${PORT}`);
  console.log(`🎓 Egerton SmartSphere - Complete Academic Management System`);
});
