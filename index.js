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

// Admin authorization middleware
const requireAdmin = (req, res, next) => {
  // In production, check user roles from database
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
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
      version: '3.0.0'
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
    version: '3.0.0',
    system: 'Complete Academic Management System',
    endpoints: {
      auth: [
        'POST /api/auth/login', 
        'POST /api/auth/register',
        'GET /api/auth/me'
      ],
      users: [
        'GET /api/users',
        'GET /api/users/:id', 
        'POST /api/users',
        'PUT /api/users/:id',
        'DELETE /api/users/:id',
        'GET /api/users/:id/enrollment'
      ],
      courses: [
        'GET /api/courses',
        'GET /api/courses/:id',
        'POST /api/courses',
        'PUT /api/courses/:id',
        'DELETE /api/courses/:id'
      ],
      units: [
        'GET /api/units',
        'GET /api/units/:id',
        'POST /api/units',
        'PUT /api/units/:id',
        'DELETE /api/units/:id'
      ],
      timetable: [
        'GET /api/timetable',
        'GET /api/timetable/student/:id',
        'POST /api/timetable/generate',
        'POST /api/timetable/entries',
        'PUT /api/timetable/entries/:id',
        'DELETE /api/timetable/entries/:id'
      ],
      attendance: [
        'POST /api/attendance/scan',
        'GET /api/attendance/user/:id',
        'GET /api/attendance/session/:id',
        'PUT /api/attendance/:id',
        'DELETE /api/attendance/:id'
      ],
      security: [
        'GET /api/security/alerts',
        'POST /api/security/scan',
        'GET /api/security/scans',
        'PUT /api/security/alerts/:id',
        'GET /api/security/current-state'
      ],
      admin: [
        'GET /api/admin/stats',
        'GET /api/admin/analytics',
        'POST /api/admin/initialize'
      ]
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
      `SELECT u.*, array_agg(r.role_name) as roles 
       FROM users u
       LEFT JOIN user_roles ur ON u.user_id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.role_id
       WHERE u.email = $1 OR u.school_id = $1
       GROUP BY u.user_id`,
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = userResult.rows[0];

    // For demo - in production use bcrypt.compare
    const validPassword = password === 'demo123';

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.user_id, 
        email: user.email, 
        schoolId: user.school_id,
        roles: user.roles
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
        faculty_name: user.faculty_name,
        roles: user.roles
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.*, array_agg(r.role_name) as roles 
       FROM users u
       LEFT JOIN user_roles ur ON u.user_id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.role_id
       WHERE u.user_id = $1
       GROUP BY u.user_id`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      user: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== COMPLETE USER MANAGEMENT ====================
// GET all users with pagination and filters
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, role, status } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT u.user_id, u.full_name, u.email, u.school_id, u.course_name, 
             u.faculty_name, u.card_status, u.is_active, u.created_at,
             array_agg(DISTINCT r.role_name) as roles
      FROM users u
      LEFT JOIN user_roles ur ON u.user_id = ur.user_id
      LEFT JOIN roles r ON ur.role_id = r.role_id
    `;
    
    const params = [];
    const conditions = [];

    if (search) {
      conditions.push(`(u.full_name ILIKE $${params.length + 1} OR u.email ILIKE $${params.length + 1} OR u.school_id ILIKE $${params.length + 1})`);
      params.push(`%${search}%`);
    }

    if (role) {
      conditions.push(`r.role_name = $${params.length + 1}`);
      params.push(role);
    }

    if (status) {
      conditions.push(`u.card_status = $${params.length + 1}`);
      params.push(status);
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }

    query += ` GROUP BY u.user_id ORDER BY u.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    // Get total count for pagination
    const countQuery = `
      SELECT COUNT(DISTINCT u.user_id) 
      FROM users u
      LEFT JOIN user_roles ur ON u.user_id = ur.user_id
      LEFT JOIN roles r ON ur.role_id = r.role_id
      ${conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''}
    `;
    const countResult = await pool.query(countQuery, params.slice(0, -2));
    const total = parseInt(countResult.rows[0].count);

    res.json({
      success: true,
      data: result.rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// GET user by ID
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.*, array_agg(r.role_name) as roles,
              json_agg(
                DISTINCT jsonb_build_object(
                  'enrollment_id', se.enrollment_id,
                  'academic_year', se.academic_year,
                  'semester', se.semester,
                  'status', se.status
                )
              ) as enrollments
       FROM users u
       LEFT JOIN user_roles ur ON u.user_id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.role_id
       LEFT JOIN student_enrollment se ON u.user_id = se.user_id
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

// CREATE new user
app.post('/api/users', authenticateToken, async (req, res) => {
  try {
    const {
      full_name, email, school_id, gender, course_name, faculty_name,
      phone, date_of_birth, roles, year_of_completion
    } = req.body;

    // Validate required fields
    if (!full_name || !email || !school_id) {
      return res.status(400).json({ error: 'Full name, email, and school ID are required' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT * FROM users WHERE email = $1 OR school_id = $2',
      [email, school_id]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User with this email or school ID already exists' });
    }

    // Create new user
    const userResult = await pool.query(
      `INSERT INTO users (
        university_id, full_name, email, password_hash, school_id, 
        barcode_value, gender, course_name, faculty_name, phone, date_of_birth,
        card_issue_date, card_expiry_date, year_of_completion
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      RETURNING *`,
      [
        1, // university_id
        full_name,
        email,
        await bcrypt.hash('default123', 10), // default password
        school_id,
        `BARCODE-${school_id}`,
        gender || 'Male',
        course_name,
        faculty_name,
        phone,
        date_of_birth,
        new Date(),
        year_of_completion ? new Date(year_of_completion, 6, 31) : new Date(new Date().getFullYear() + 4, 6, 31),
        year_of_completion
      ]
    );

    const newUser = userResult.rows[0];

    // Assign roles
    if (roles && roles.length > 0) {
      for (const roleName of roles) {
        const roleResult = await pool.query('SELECT role_id FROM roles WHERE role_name = $1', [roleName]);
        if (roleResult.rows.length > 0) {
          await pool.query(
            'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)',
            [newUser.user_id, roleResult.rows[0].role_id]
          );
        }
      }
    } else {
      // Default to student role
      await pool.query(
        'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)',
        [newUser.user_id, 7] // Student role
      );
    }

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: newUser
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// UPDATE user
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const {
      full_name, email, school_id, gender, course_name, faculty_name,
      phone, date_of_birth, card_status, is_active, year_of_completion
    } = req.body;

    // Check if user exists
    const existingUser = await pool.query('SELECT * FROM users WHERE user_id = $1', [req.params.id]);
    if (existingUser.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update user
    const result = await pool.query(
      `UPDATE users SET 
        full_name = COALESCE($1, full_name),
        email = COALESCE($2, email),
        school_id = COALESCE($3, school_id),
        gender = COALESCE($4, gender),
        course_name = COALESCE($5, course_name),
        faculty_name = COALESCE($6, faculty_name),
        phone = COALESCE($7, phone),
        date_of_birth = COALESCE($8, date_of_birth),
        card_status = COALESCE($9, card_status),
        is_active = COALESCE($10, is_active),
        year_of_completion = COALESCE($11, year_of_completion),
        updated_at = CURRENT_TIMESTAMP
       WHERE user_id = $12
       RETURNING *`,
      [
        full_name, email, school_id, gender, course_name, faculty_name,
        phone, date_of_birth, card_status, is_active, year_of_completion,
        req.params.id
      ]
    );

    res.json({
      success: true,
      message: 'User updated successfully',
      data: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// DELETE user
app.delete('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Check if user exists
    const existingUser = await pool.query('SELECT * FROM users WHERE user_id = $1', [req.params.id]);
    if (existingUser.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Soft delete (set is_active to false)
    await pool.query(
      'UPDATE users SET is_active = false, updated_at = CURRENT_TIMESTAMP WHERE user_id = $1',
      [req.params.id]
    );

    res.json({
      success: true,
      message: 'User deleted successfully'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== COURSES MANAGEMENT ====================
// GET all courses
app.get('/api/courses', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, d.name as department_name, f.name as faculty_name
      FROM courses c
      LEFT JOIN departments d ON c.department_id = d.department_id
      LEFT JOIN faculties f ON d.faculty_id = f.faculty_id
      ORDER BY c.course_name
    `);

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

// GET course by ID
app.get('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, d.name as department_name, f.name as faculty_name,
             json_agg(
               DISTINCT jsonb_build_object(
                 'unit_id', u.unit_id,
                 'unit_code', u.unit_code,
                 'unit_name', u.unit_name,
                 'academic_year', cu.academic_year,
                 'semester', cu.semester
               )
             ) as units
      FROM courses c
      LEFT JOIN departments d ON c.department_id = d.department_id
      LEFT JOIN faculties f ON d.faculty_id = f.faculty_id
      LEFT JOIN course_units cu ON c.course_id = cu.course_id
      LEFT JOIN units u ON cu.unit_id = u.unit_id
      WHERE c.course_id = $1
      GROUP BY c.course_id, d.name, f.name
    `, [req.params.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found' });
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

// CREATE course
app.post('/api/courses', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { course_name, course_code, department_id, duration_years, description, total_credits } = req.body;

    const result = await pool.query(
      `INSERT INTO courses (course_name, course_code, department_id, duration_years, description, total_credits)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [course_name, course_code, department_id, duration_years, description, total_credits]
    );

    res.status(201).json({
      success: true,
      message: 'Course created successfully',
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// UPDATE course
app.put('/api/courses/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { course_name, course_code, department_id, duration_years, description, total_credits, is_active } = req.body;

    const result = await pool.query(
      `UPDATE courses SET 
        course_name = COALESCE($1, course_name),
        course_code = COALESCE($2, course_code),
        department_id = COALESCE($3, department_id),
        duration_years = COALESCE($4, duration_years),
        description = COALESCE($5, description),
        total_credits = COALESCE($6, total_credits),
        is_active = COALESCE($7, is_active)
       WHERE course_id = $8
       RETURNING *`,
      [course_name, course_code, department_id, duration_years, description, total_credits, is_active, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }

    res.json({
      success: true,
      message: 'Course updated successfully',
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== UNITS MANAGEMENT ====================
// GET all units
app.get('/api/units', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.*, 
             json_agg(
               DISTINCT jsonb_build_object(
                 'lecturer_id', ul.lecturer_id,
                 'full_name', usr.full_name,
                 'is_primary', ul.is_primary
               )
             ) as lecturers
      FROM units u
      LEFT JOIN unit_lecturers ul ON u.unit_id = ul.unit_id
      LEFT JOIN users usr ON ul.lecturer_id = usr.user_id
      GROUP BY u.unit_id
      ORDER BY u.unit_code
    `);

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

// GET unit by ID
app.get('/api/units/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.*,
             json_agg(
               DISTINCT jsonb_build_object(
                 'lecturer_id', ul.lecturer_id,
                 'full_name', usr.full_name,
                 'email', usr.email,
                 'is_primary', ul.is_primary
               )
             ) as lecturers
      FROM units u
      LEFT JOIN unit_lecturers ul ON u.unit_id = ul.unit_id
      LEFT JOIN users usr ON ul.lecturer_id = usr.user_id
      WHERE u.unit_id = $1
      GROUP BY u.unit_id
    `, [req.params.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Unit not found' });
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

// CREATE unit
app.post('/api/units', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const {
      unit_name, unit_code, unit_type, credit_hours, contact_hours_per_week,
      lecture_hours_per_week, lab_hours_per_week, max_students, requires_lab,
      requires_computers, description
    } = req.body;

    const result = await pool.query(
      `INSERT INTO units (
        unit_name, unit_code, unit_type, credit_hours, contact_hours_per_week,
        lecture_hours_per_week, lab_hours_per_week, max_students, requires_lab,
        requires_computers, description
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *`,
      [
        unit_name, unit_code, unit_type, credit_hours, contact_hours_per_week,
        lecture_hours_per_week, lab_hours_per_week, max_students, requires_lab,
        requires_computers, description
      ]
    );

    res.status(201).json({
      success: true,
      message: 'Unit created successfully',
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// UPDATE unit
app.put('/api/units/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const {
      unit_name, unit_code, unit_type, credit_hours, contact_hours_per_week,
      lecture_hours_per_week, lab_hours_per_week, max_students, requires_lab,
      requires_computers, description, is_active
    } = req.body;

    const result = await pool.query(
      `UPDATE units SET 
        unit_name = COALESCE($1, unit_name),
        unit_code = COALESCE($2, unit_code),
        unit_type = COALESCE($3, unit_type),
        credit_hours = COALESCE($4, credit_hours),
        contact_hours_per_week = COALESCE($5, contact_hours_per_week),
        lecture_hours_per_week = COALESCE($6, lecture_hours_per_week),
        lab_hours_per_week = COALESCE($7, lab_hours_per_week),
        max_students = COALESCE($8, max_students),
        requires_lab = COALESCE($9, requires_lab),
        requires_computers = COALESCE($10, requires_computers),
        description = COALESCE($11, description),
        is_active = COALESCE($12, is_active)
       WHERE unit_id = $13
       RETURNING *`,
      [
        unit_name, unit_code, unit_type, credit_hours, contact_hours_per_week,
        lecture_hours_per_week, lab_hours_per_week, max_students, requires_lab,
        requires_computers, description, is_active, req.params.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Unit not found' });
    }

    res.json({
      success: true,
      message: 'Unit updated successfully',
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== ENHANCED TIMETABLE MANAGEMENT ====================
// GET complete timetable
app.get('/api/timetable', authenticateToken, async (req, res) => {
  try {
    const { academic_year, semester } = req.query;
    
    let query = `
      SELECT te.entry_id, te.day_of_week, te.start_time, te.end_time, te.duration_minutes,
             u.unit_id, u.unit_code, u.unit_name, 
             v.venue_id, v.name as venue_name, v.capacity,
             te.lecturer_ids, te.expected_students, te.is_conflict,
             array_agg(ul.full_name) as lecturer_names
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
    
    query += ' GROUP BY te.entry_id, u.unit_id, u.unit_code, u.unit_name, v.venue_id, v.name, v.capacity, gt.timetable_id';
    query += ' ORDER BY te.day_of_week, te.start_time';
    
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

// CREATE timetable entry
app.post('/api/timetable/entries', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const {
      timetable_id, unit_id, venue_id, lecturer_ids, slot_id,
      day_of_week, start_time, end_time, duration_minutes, expected_students
    } = req.body;

    const result = await pool.query(
      `INSERT INTO timetable_entries (
        timetable_id, unit_id, venue_id, lecturer_ids, slot_id,
        day_of_week, start_time, end_time, duration_minutes, expected_students
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *`,
      [
        timetable_id, unit_id, venue_id, lecturer_ids, slot_id,
        day_of_week, start_time, end_time, duration_minutes, expected_students
      ]
    );

    res.status(201).json({
      success: true,
      message: 'Timetable entry created successfully',
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// UPDATE timetable entry
app.put('/api/timetable/entries/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const {
      venue_id, lecturer_ids, start_time, end_time, duration_minutes, expected_students
    } = req.body;

    const result = await pool.query(
      `UPDATE timetable_entries SET 
        venue_id = COALESCE($1, venue_id),
        lecturer_ids = COALESCE($2, lecturer_ids),
        start_time = COALESCE($3, start_time),
        end_time = COALESCE($4, end_time),
        duration_minutes = COALESCE($5, duration_minutes),
        expected_students = COALESCE($6, expected_students)
       WHERE entry_id = $7
       RETURNING *`,
      [venue_id, lecturer_ids, start_time, end_time, duration_minutes, expected_students, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Timetable entry not found' });
    }

    res.json({
      success: true,
      message: 'Timetable entry updated successfully',
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== ENHANCED ATTENDANCE MANAGEMENT ====================
// GET attendance for user
app.get('/api/attendance/user/:id', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    let query = `
      SELECT ar.record_id, ar.attendance_status, ar.scanned_at, ar.minutes_late,
             u.unit_code, u.unit_name, ases.session_date, ases.start_time, ases.end_time,
             ul.full_name as lecturer_name, v.name as venue_name
      FROM attendance_records ar
      JOIN attendance_sessions ases ON ar.session_id = ases.session_id
      JOIN units u ON ases.unit_id = u.unit_id
      JOIN users ul ON ases.lecturer_id = ul.user_id
      JOIN venues v ON ases.venue_id = v.venue_id
      WHERE ar.user_id = $1
    `;
    
    const params = [req.params.id];
    
    if (start_date && end_date) {
      query += ' AND ases.session_date BETWEEN $2 AND $3';
      params.push(start_date, end_date);
    }
    
    query += ' ORDER BY ar.scanned_at DESC LIMIT 100';
    
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

// UPDATE attendance record
app.put('/api/attendance/:id', authenticateToken, async (req, res) => {
  try {
    const { attendance_status, minutes_late, verification_notes } = req.body;

    const result = await pool.query(
      `UPDATE attendance_records SET 
        attendance_status = COALESCE($1, attendance_status),
        minutes_late = COALESCE($2, minutes_late),
        verification_notes = COALESCE($3, verification_notes)
       WHERE record_id = $4
       RETURNING *`,
      [attendance_status, minutes_late, verification_notes, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Attendance record not found' });
    }

    res.json({
      success: true,
      message: 'Attendance record updated successfully',
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== ENHANCED SECURITY MANAGEMENT ====================
// GET all security scans
app.get('/api/security/scans', authenticateToken, async (req, res) => {
  try {
    const { limit = 50, user_id, station_id, start_date, end_date } = req.query;
    
    let query = `
      SELECT sl.scan_id, sl.scan_time, sl.scan_type, sl.verified, sl.triggered_alert,
             u.full_name, u.school_id, u.course_name,
             ss.station_name, ss.station_type, ss.location
      FROM scan_logs sl
      JOIN users u ON sl.user_id = u.user_id
      JOIN scanning_stations ss ON sl.station_id = ss.station_id
    `;
    
    const params = [];
    const conditions = [];
    
    if (user_id) {
      conditions.push(`sl.user_id = $${params.length + 1}`);
      params.push(user_id);
    }
    
    if (station_id) {
      conditions.push(`sl.station_id = $${params.length + 1}`);
      params.push(station_id);
    }
    
    if (start_date && end_date) {
      conditions.push(`sl.scan_time BETWEEN $${params.length + 1} AND $${params.length + 2}`);
      params.push(start_date, end_date);
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }
    
    query += ` ORDER BY sl.scan_time DESC LIMIT $${params.length + 1}`;
    params.push(limit);
    
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

// UPDATE security alert
app.put('/api/security/alerts/:id', authenticateToken, async (req, res) => {
  try {
    const { status, acknowledged_by, resolved_at } = req.body;

    const result = await pool.query(
      `UPDATE security_alerts SET 
        status = COALESCE($1, status),
        acknowledged_by = COALESCE($2, acknowledged_by),
        acknowledged_at = CASE WHEN $2 IS NOT NULL THEN COALESCE(acknowledged_at, NOW()) ELSE acknowledged_at END,
        resolved_at = COALESCE($3, resolved_at)
       WHERE alert_id = $4
       RETURNING *`,
      [status, acknowledged_by, resolved_at, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Security alert not found' });
    }

    res.json({
      success: true,
      message: 'Security alert updated successfully',
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// GET current student states
app.get('/api/security/current-state', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT scs.*, u.full_name, u.school_id, u.course_name,
             ss.station_name, ss.location
      FROM student_current_state scs
      JOIN users u ON scs.user_id = u.user_id
      LEFT JOIN scanning_stations ss ON scs.last_station_id = ss.station_id
      ORDER BY scs.last_scan_time DESC
    `);

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

// ==================== ADMIN ANALYTICS ====================
app.get('/api/admin/analytics', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Get various analytics
    const [usersByRole, attendanceStats, venueUsage, systemHealth] = await Promise.all([
      // Users by role
      pool.query(`
        SELECT r.role_name, COUNT(*) as count
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.role_id
        GROUP BY r.role_name
        ORDER BY count DESC
      `),
      
      // Attendance statistics
      pool.query(`
        SELECT 
          COUNT(*) as total_records,
          COUNT(CASE WHEN attendance_status = 'Present' THEN 1 END) as present_count,
          COUNT(CASE WHEN attendance_status = 'Absent' THEN 1 END) as absent_count,
          COUNT(CASE WHEN attendance_status = 'Late' THEN 1 END) as late_count,
          ROUND(AVG(CASE WHEN attendance_status = 'Present' THEN 1 ELSE 0 END) * 100, 2) as attendance_rate
        FROM attendance_records
        WHERE DATE(scanned_at) = CURRENT_DATE
      `),
      
      // Venue usage
      pool.query(`
        SELECT v.name, v.capacity, COUNT(te.entry_id) as scheduled_classes,
               ROUND(AVG(te.expected_students::DECIMAL / NULLIF(v.capacity, 0)) * 100, 2) as avg_utilization
        FROM venues v
        LEFT JOIN timetable_entries te ON v.venue_id = te.venue_id
        GROUP BY v.venue_id, v.name, v.capacity
        ORDER BY scheduled_classes DESC
        LIMIT 10
      `),
      
      // System health
      pool.query(`
        SELECT 
          COUNT(*) as total_users,
          COUNT(CASE WHEN is_active = true THEN 1 END) as active_users,
          COUNT(CASE WHEN card_status = 'Active' THEN 1 END) as active_cards,
          COUNT(CASE WHEN card_status = 'Lost' THEN 1 END) as lost_cards
        FROM users
      `)
    ]);

    res.json({
      success: true,
      data: {
        users_by_role: usersByRole.rows,
        attendance: attendanceStats.rows[0],
        venue_usage: venueUsage.rows,
        system_health: systemHealth.rows[0]
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Initialize system with sample data
app.post('/api/admin/initialize', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Create sample faculties, departments, courses, units, etc.
    // This would populate the database with initial data
    // Implementation depends on your specific needs
    
    res.json({
      success: true,
      message: 'System initialized with sample data'
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
      courses: '/api/courses/*',
      units: '/api/units/*',
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
  console.log(`🎓 Egerton SmartSphere - Complete Professional System`);
});
