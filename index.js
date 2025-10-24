const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
const geoip = require('geoip-lite');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Enhanced security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(compression());
app.use(morgan('combined'));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: 'Too many requests, please slow down.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Database connection with enhanced configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20,
  allowExitOnIdle: true
});

// Enhanced JWT Authentication Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false,
      error: 'ACCESS_TOKEN_REQUIRED',
      message: 'Authentication token is required'
    });
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    
    // Verify user still exists and is active
    const userResult = await pool.query(
      `SELECT u.user_id, u.is_active, u.card_status, array_agg(r.role_name) as roles
       FROM users u
       LEFT JOIN user_roles ur ON u.user_id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.role_id
       WHERE u.user_id = $1
       GROUP BY u.user_id`,
      [user.userId]
    );

    if (userResult.rows.length === 0 || !userResult.rows[0].is_active) {
      return res.status(403).json({
        success: false,
        error: 'USER_INACTIVE',
        message: 'User account is inactive'
      });
    }

    req.user = {
      ...user,
      roles: userResult.rows[0].roles,
      cardStatus: userResult.rows[0].card_status
    };
    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      error: 'INVALID_TOKEN',
      message: 'Invalid or expired authentication token'
    });
  }
};

// Role-based authorization middleware
const requireRoles = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.roles) {
      return res.status(403).json({
        success: false,
        error: 'ACCESS_DENIED',
        message: 'Insufficient permissions'
      });
    }

    const hasRequiredRole = allowedRoles.some(role => 
      req.user.roles.includes(role)
    );

    if (!hasRequiredRole) {
      return res.status(403).json({
        success: false,
        error: 'INSUFFICIENT_PERMISSIONS',
        message: `Required roles: ${allowedRoles.join(', ')}`
      });
    }
    next();
  };
};

// Security-specific middleware
const securityContext = (req, res, next) => {
  req.securityContext = {
    timestamp: new Date(),
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    location: geoip.lookup(req.ip) || {}
  };
  next();
};

// ==================== ENHANCED SECURITY TABLES SETUP ====================
const initializeSecurityTables = async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Security Stations Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS security_stations (
        station_id VARCHAR(50) PRIMARY KEY,
        station_name VARCHAR(100) NOT NULL,
        location VARCHAR(200) NOT NULL,
        station_type station_type_enum NOT NULL,
        building_type VARCHAR(50) NOT NULL,
        gender_restriction gender_restriction_type DEFAULT 'None',
        gps_coordinates POINT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Enhanced Security Movement Logs
    await client.query(`
      CREATE TABLE IF NOT EXISTS security_movement_logs (
        log_id BIGSERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(user_id),
        station_id VARCHAR(50) NOT NULL REFERENCES security_stations(station_id),
        scan_type scan_type_enum NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        session_id VARCHAR(100),
        gps_location POINT,
        device_id VARCHAR(100),
        verified BOOLEAN DEFAULT TRUE,
        is_suspicious BOOLEAN DEFAULT FALSE,
        suspicion_reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Enhanced Security Alerts
    await client.query(`
      CREATE TABLE IF NOT EXISTS security_alerts (
        alert_id BIGSERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(user_id),
        alert_type alert_type_enum NOT NULL,
        alert_message TEXT NOT NULL,
        severity alert_severity_type NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        location VARCHAR(200),
        station_id VARCHAR(50) REFERENCES security_stations(station_id),
        is_resolved BOOLEAN DEFAULT FALSE,
        resolved_by INTEGER REFERENCES users(user_id),
        resolved_at TIMESTAMP,
        resolution_notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Card Suspension System
    await client.query(`
      CREATE TABLE IF NOT EXISTS card_suspension_logs (
        suspension_id BIGSERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(user_id),
        suspended_by VARCHAR(50) NOT NULL, -- 'student' or user_id
        suspension_reason TEXT NOT NULL,
        suspension_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_time TIMESTAMP,
        resolved_by INTEGER REFERENCES users(user_id),
        resolution_notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Curfew Rules
    await client.query(`
      CREATE TABLE IF NOT EXISTS curfew_rules (
        rule_id SERIAL PRIMARY KEY,
        building_type VARCHAR(50) NOT NULL,
        restricted_gender gender_type NOT NULL,
        start_time TIME NOT NULL,
        end_time TIME NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Student Current State Tracking
    await client.query(`
      CREATE TABLE IF NOT EXISTS student_current_state (
        user_id INTEGER PRIMARY KEY REFERENCES users(user_id),
        current_status status_enum DEFAULT 'Outside',
        last_station_id VARCHAR(50) REFERENCES security_stations(station_id),
        last_scan_time TIMESTAMP,
        current_session_id VARCHAR(100),
        expected_venue VARCHAR(100),
        last_known_location POINT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query('COMMIT');
    console.log('✅ Security tables initialized successfully');
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error initializing security tables:', error);
    throw error;
  } finally {
    client.release();
  }
};

// ==================== ADVANCED SECURITY ALGORITHMS ====================
class SecurityIntelligenceEngine {
  static async detectImpossibleMovement(userId, currentStation, currentTime) {
    const client = await pool.connect();
    try {
      // Get recent movements (last 30 minutes)
      const recentMovements = await client.query(
        `SELECT sml.station_id, sml.timestamp, ss.location, ss.building_type
         FROM security_movement_logs sml
         JOIN security_stations ss ON sml.station_id = ss.station_id
         WHERE sml.user_id = $1 AND sml.timestamp > $2
         ORDER BY sml.timestamp DESC
         LIMIT 5`,
        [userId, new Date(Date.now() - 30 * 60 * 1000)]
      );

      if (recentMovements.rows.length < 2) return null;

      const lastMovement = recentMovements.rows[0];
      const timeDiff = (currentTime - lastMovement.timestamp) / (1000 * 60); // minutes

      // Calculate minimum travel time between stations (simplified)
      const minTravelTime = this.calculateMinTravelTime(lastMovement.location, currentStation.location);

      if (timeDiff < minTravelTime) {
        return {
          type: 'IMPOSSIBLE_MOVEMENT',
          severity: 'High',
          message: `Student moved from ${lastMovement.building_type} to ${currentStation.building_type} in ${timeDiff.toFixed(1)} minutes (minimum: ${minTravelTime} minutes)`,
          details: {
            fromStation: lastMovement.station_id,
            toStation: currentStation.station_id,
            actualTime: timeDiff,
            expectedMinTime: minTravelTime
          }
        };
      }

      return null;
    } finally {
      client.release();
    }
  }

  static calculateMinTravelTime(fromLocation, toLocation) {
    // Simplified calculation - in production, use actual coordinates and routing
    const baseTime = 2; // minutes between adjacent buildings
    return baseTime;
  }

  static async checkCurfewViolation(userId, station, currentTime) {
    const client = await pool.connect();
    try {
      const userResult = await client.query(
        'SELECT gender FROM users WHERE user_id = $1',
        [userId]
      );

      if (userResult.rows.length === 0) return null;

      const userGender = userResult.rows[0].gender;
      const currentHour = currentTime.getHours();

      // Check curfew rules for this station type
      const curfewRules = await client.query(
        `SELECT * FROM curfew_rules 
         WHERE building_type = $1 AND restricted_gender = $2 AND is_active = TRUE`,
        [station.building_type, userGender]
      );

      for (const rule of curfewRules.rows) {
        const startHour = parseInt(rule.start_time.split(':')[0]);
        const endHour = parseInt(rule.end_time.split(':')[0]);

        if (currentHour >= startHour || currentHour < endHour) {
          return {
            type: 'CURFEW_VIOLATION',
            severity: 'Medium',
            message: `${userGender} student found in ${station.building_type} during restricted hours (${rule.start_time} - ${rule.end_time})`,
            details: {
              restrictedHours: `${rule.start_time} - ${rule.end_time}`,
              currentTime: currentTime.toTimeString().split(' ')[0]
            }
          };
        }
      }

      return null;
    } finally {
      client.release();
    }
  }

  static async detectDuplicateUsage(userId, currentStation, currentTime) {
    const client = await pool.connect();
    try {
      // Check for active sessions in other locations
      const activeSessions = await client.query(
        `SELECT COUNT(*) as active_count 
         FROM student_current_state scs
         JOIN security_stations ss ON scs.last_station_id = ss.station_id
         WHERE scs.user_id = $1 AND scs.current_status = 'Inside' 
         AND ss.station_id != $2`,
        [userId, currentStation.station_id]
      );

      if (parseInt(activeSessions.rows[0].active_count) > 0) {
        return {
          type: 'DUPLICATE_CARD_USAGE',
          severity: 'Critical',
          message: 'Card appears to be used simultaneously in multiple locations',
          details: {
            currentStation: currentStation.station_id,
            suspiciousActivity: 'Possible card sharing or cloning'
          }
        };
      }

      return null;
    } finally {
      client.release();
    }
  }
}

// ==================== ENHANCED SECURITY ENDPOINTS ====================
app.use('/api/security', authLimiter);
app.use('/api', apiLimiter);

// SECURITY SCAN ENDPOINT - Core of the security system
app.post('/api/security/scan', authenticateToken, securityContext, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { barcode_value, station_id, scan_type, gps_location, device_id } = req.body;

    // Validate scan data
    if (!barcode_value || !station_id || !scan_type) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_REQUIRED_FIELDS',
        message: 'Barcode value, station ID, and scan type are required'
      });
    }

    // Verify user exists and card is active
    const userResult = await client.query(
      `SELECT u.*, array_agg(r.role_name) as roles
       FROM users u
       LEFT JOIN user_roles ur ON u.user_id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.role_id
       WHERE u.barcode_value = $1 AND u.is_active = TRUE
       GROUP BY u.user_id`,
      [barcode_value]
    );

    if (userResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'Invalid barcode or user not found'
      });
    }

    const user = userResult.rows[0];

    // Check card status
    if (user.card_status !== 'Active') {
      await client.query(
        `INSERT INTO security_alerts (user_id, alert_type, alert_message, severity, location, station_id)
         VALUES ($1, 'LostCardUsed', 'Suspended card attempted to be used', 'Critical', $2, $3)`,
        [user.user_id, req.securityContext.location, station_id]
      );
      await client.query('COMMIT');

      return res.status(403).json({
        success: false,
        error: 'CARD_SUSPENDED',
        message: `Card status: ${user.card_status}. Access denied.`,
        alert_triggered: true
      });
    }

    // Verify station exists
    const stationResult = await client.query(
      'SELECT * FROM security_stations WHERE station_id = $1 AND is_active = TRUE',
      [station_id]
    );

    if (stationResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({
        success: false,
        error: 'STATION_NOT_FOUND',
        message: 'Security station not found or inactive'
      });
    }

    const station = stationResult.rows[0];
    const currentTime = new Date();

    // Run security intelligence checks
    const alerts = [];
    
    const movementAlert = await SecurityIntelligenceEngine.detectImpossibleMovement(
      user.user_id, station, currentTime
    );
    if (movementAlert) alerts.push(movementAlert);

    const curfewAlert = await SecurityIntelligenceEngine.checkCurfewViolation(
      user.user_id, station, currentTime
    );
    if (curfewAlert) alerts.push(curfewAlert);

    const duplicateAlert = await SecurityIntelligenceEngine.detectDuplicateUsage(
      user.user_id, station, currentTime
    );
    if (duplicateAlert) alerts.push(duplicateAlert);

    // Log the movement
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    await client.query(
      `INSERT INTO security_movement_logs 
       (user_id, station_id, scan_type, session_id, gps_location, device_id, is_suspicious)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        user.user_id,
        station_id,
        scan_type,
        sessionId,
        gps_location ? `(${gps_location.lng},${gps_location.lat})` : null,
        device_id,
        alerts.length > 0
      ]
    );

    // Update student current state
    const newStatus = scan_type === 'Entry' ? 'Inside' : 'Outside';
    
    await client.query(
      `INSERT INTO student_current_state 
       (user_id, current_status, last_station_id, last_scan_time, current_session_id, last_known_location)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (user_id) 
       DO UPDATE SET 
         current_status = $2,
         last_station_id = $3,
         last_scan_time = $4,
         current_session_id = $5,
         last_known_location = $6,
         updated_at = CURRENT_TIMESTAMP`,
      [
        user.user_id,
        newStatus,
        station_id,
        currentTime,
        scan_type === 'Entry' ? sessionId : null,
        gps_location ? `(${gps_location.lng},${gps_location.lat})` : null
      ]
    );

    // Create alerts for any detected issues
    for (const alert of alerts) {
      await client.query(
        `INSERT INTO security_alerts 
         (user_id, alert_type, alert_message, severity, location, station_id)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          user.user_id,
          alert.type,
          alert.message,
          alert.severity,
          req.securityContext.location,
          station_id
        ]
      );
    }

    await client.query('COMMIT');

    res.json({
      success: true,
      message: `Scan ${scan_type.toLowerCase()} recorded successfully`,
      data: {
        user: {
          id: user.user_id,
          name: user.full_name,
          school_id: user.school_id,
          course: user.course_name
        },
        station: {
          id: station.station_id,
          name: station.station_name,
          type: station.station_type
        },
        scan: {
          type: scan_type,
          time: currentTime,
          session_id: sessionId
        },
        alerts: alerts.length > 0 ? alerts : undefined,
        access_granted: alerts.length === 0
      }
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Security scan error:', error);
    res.status(500).json({
      success: false,
      error: 'SCAN_PROCESSING_ERROR',
      message: 'Error processing security scan'
    });
  } finally {
    client.release();
  }
});

// CARD MANAGEMENT ENDPOINTS
app.post('/api/security/cards/:id/suspend', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { reason } = req.body;
    const userId = req.params.id;

    // Verify user exists
    const userResult = await client.query(
      'SELECT * FROM users WHERE user_id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'User not found'
      });
    }

    // Suspend card
    await client.query(
      'UPDATE users SET card_status = $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2',
      ['Lost', userId]
    );

    // Log suspension
    const suspendedBy = req.user.roles.includes('admin') ? req.user.userId.toString() : 'student';
    
    await client.query(
      `INSERT INTO card_suspension_logs 
       (user_id, suspended_by, suspension_reason)
       VALUES ($1, $2, $3)`,
      [userId, suspendedBy, reason || 'Reported by user']
    );

    // Create security alert
    await client.query(
      `INSERT INTO security_alerts 
       (user_id, alert_type, alert_message, severity)
       VALUES ($1, 'LostCardUsed', 'Card suspended and marked as lost', 'High')`,
      [userId]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      message: 'Card suspended successfully',
      data: {
        user_id: userId,
        card_status: 'Lost',
        suspended_at: new Date(),
        suspended_by: suspendedBy
      }
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Card suspension error:', error);
    res.status(500).json({
      success: false,
      error: 'CARD_SUSPENSION_ERROR',
      message: 'Error suspending card'
    });
  } finally {
    client.release();
  }
});

// SECURITY DASHBOARD ENDPOINTS
app.get('/api/security/alerts', authenticateToken, requireRoles(['admin', 'security']), async (req, res) => {
  try {
    const { status, severity, start_date, end_date, page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT sa.*, u.full_name, u.school_id, u.course_name,
             ss.station_name, ss.location as station_location,
             resolver.full_name as resolved_by_name
      FROM security_alerts sa
      LEFT JOIN users u ON sa.user_id = u.user_id
      LEFT JOIN security_stations ss ON sa.station_id = ss.station_id
      LEFT JOIN users resolver ON sa.resolved_by = resolver.user_id
    `;
    
    const params = [];
    const conditions = [];

    if (status) {
      conditions.push(`sa.is_resolved = $${params.length + 1}`);
      params.push(status === 'resolved');
    }

    if (severity) {
      conditions.push(`sa.severity = $${params.length + 1}`);
      params.push(severity);
    }

    if (start_date && end_date) {
      conditions.push(`sa.timestamp BETWEEN $${params.length + 1} AND $${params.length + 2}`);
      params.push(start_date, end_date);
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }

    query += ` ORDER BY sa.timestamp DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    // Get total count
    const countQuery = `SELECT COUNT(*) FROM security_alerts sa ${conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : ''}`;
    const countResult = await pool.query(countQuery, params.slice(0, -2));

    res.json({
      success: true,
      data: result.rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(countResult.rows[0].count),
        pages: Math.ceil(parseInt(countResult.rows[0].count) / limit)
      }
    });
  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({
      success: false,
      error: 'FETCH_ALERTS_ERROR',
      message: 'Error fetching security alerts'
    });
  }
});

// REAL-TIME STUDENT TRACKING
app.get('/api/security/current-state', authenticateToken, requireRoles(['admin', 'security']), async (req, res) => {
  try {
    const { building, status, page = 1, limit = 100 } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT scs.*, u.full_name, u.school_id, u.course_name, u.gender,
             ss.station_name, ss.location, ss.building_type,
             EXTRACT(EPOCH FROM (NOW() - scs.last_scan_time))/60 as minutes_since_last_scan
      FROM student_current_state scs
      JOIN users u ON scs.user_id = u.user_id
      LEFT JOIN security_stations ss ON scs.last_station_id = ss.station_id
      WHERE u.is_active = TRUE
    `;
    
    const params = [];

    if (building) {
      query += ` AND ss.building_type = $${params.length + 1}`;
      params.push(building);
    }

    if (status) {
      query += ` AND scs.current_status = $${params.length + 1}`;
      params.push(status);
    }

    query += ` ORDER BY scs.last_scan_time DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    res.json({
      success: true,
      data: result.rows,
      summary: {
        total_inside: result.rows.filter(r => r.current_status === 'Inside').length,
        total_outside: result.rows.filter(r => r.current_status === 'Outside').length,
        last_updated: new Date()
      }
    });
  } catch (error) {
    console.error('Current state error:', error);
    res.status(500).json({
      success: false,
      error: 'FETCH_CURRENT_STATE_ERROR',
      message: 'Error fetching current student states'
    });
  }
});

// SECURITY ANALYTICS
app.get('/api/security/analytics', authenticateToken, requireRoles(['admin', 'security']), async (req, res) => {
  try {
    const { period = 'today' } = req.query;

    const analytics = await Promise.all([
      // Alert statistics
      pool.query(`
        SELECT 
          alert_type,
          severity,
          COUNT(*) as count,
          COUNT(CASE WHEN is_resolved THEN 1 END) as resolved_count
        FROM security_alerts
        WHERE timestamp >= $1
        GROUP BY alert_type, severity
        ORDER BY count DESC
      `, [getPeriodStart(period)]),

      // Movement statistics
      pool.query(`
        SELECT 
          ss.building_type,
          sml.scan_type,
          COUNT(*) as scan_count,
          COUNT(CASE WHEN sml.is_suspicious THEN 1 END) as suspicious_count
        FROM security_movement_logs sml
        JOIN security_stations ss ON sml.station_id = ss.station_id
        WHERE sml.timestamp >= $1
        GROUP BY ss.building_type, sml.scan_type
        ORDER BY scan_count DESC
      `, [getPeriodStart(period)]),

      // Curfew violations
      pool.query(`
        SELECT 
          u.gender,
          ss.building_type,
          COUNT(*) as violation_count
        FROM security_alerts sa
        JOIN users u ON sa.user_id = u.user_id
        JOIN security_stations ss ON sa.station_id = ss.station_id
        WHERE sa.alert_type = 'CURFEW_VIOLATION' AND sa.timestamp >= $1
        GROUP BY u.gender, ss.building_type
        ORDER BY violation_count DESC
      `, [getPeriodStart(period)]),

      // System health
      pool.query(`
        SELECT 
          COUNT(*) as total_scans,
          COUNT(DISTINCT user_id) as unique_users,
          COUNT(CASE WHEN is_suspicious THEN 1 END) as suspicious_scans,
          AVG(CASE WHEN is_suspicious THEN 1 ELSE 0 END) * 100 as suspicious_percentage
        FROM security_movement_logs
        WHERE timestamp >= $1
      `, [getPeriodStart(period)])
    ]);

    res.json({
      success: true,
      data: {
        alert_statistics: analytics[0].rows,
        movement_patterns: analytics[1].rows,
        curfew_violations: analytics[2].rows,
        system_health: analytics[3].rows[0],
        period: period,
        generated_at: new Date()
      }
    });

  } catch (error) {
    console.error('Security analytics error:', error);
    res.status(500).json({
      success: false,
      error: 'ANALYTICS_ERROR',
      message: 'Error generating security analytics'
    });
  }
});

// CURFEW MANAGEMENT
app.get('/api/security/curfew-rules', authenticateToken, requireRoles(['admin']), async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM curfew_rules ORDER BY building_type, start_time');
    
    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'FETCH_CURFEW_RULES_ERROR',
      message: 'Error fetching curfew rules'
    });
  }
});

app.post('/api/security/curfew-rules', authenticateToken, requireRoles(['admin']), async (req, res) => {
  try {
    const { building_type, restricted_gender, start_time, end_time } = req.body;

    const result = await pool.query(
      `INSERT INTO curfew_rules (building_type, restricted_gender, start_time, end_time)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [building_type, restricted_gender, start_time, end_time]
    );

    res.status(201).json({
      success: true,
      message: 'Curfew rule created successfully',
      data: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'CREATE_CURFEW_RULE_ERROR',
      message: 'Error creating curfew rule'
    });
  }
});

// STATION MANAGEMENT
app.get('/api/security/stations', authenticateToken, requireRoles(['admin', 'security']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ss.*, 
             COUNT(sml.log_id) as total_scans,
             COUNT(CASE WHEN sml.is_suspicious THEN 1 END) as suspicious_scans
      FROM security_stations ss
      LEFT JOIN security_movement_logs sml ON ss.station_id = sml.station_id
      GROUP BY ss.station_id
      ORDER BY ss.station_name
    `);

    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'FETCH_STATIONS_ERROR',
      message: 'Error fetching security stations'
    });
  }
});

// ==================== ENHANCED EXISTING ENDPOINTS ====================
// Enhanced user management with security context
app.get('/api/users/:id/security-history', authenticateToken, requireRoles(['admin', 'security']), async (req, res) => {
  try {
    const { days = 30 } = req.query;
    
    const history = await pool.query(
      `SELECT sml.*, ss.station_name, ss.location, ss.building_type,
              sa.alert_type, sa.severity, sa.timestamp as alert_time
       FROM security_movement_logs sml
       JOIN security_stations ss ON sml.station_id = ss.station_id
       LEFT JOIN security_alerts sa ON sml.user_id = sa.user_id AND sa.timestamp BETWEEN sml.timestamp - INTERVAL '5 minutes' AND sml.timestamp + INTERVAL '5 minutes'
       WHERE sml.user_id = $1 AND sml.timestamp >= $2
       ORDER BY sml.timestamp DESC
       LIMIT 200`,
      [req.params.id, new Date(Date.now() - days * 24 * 60 * 60 * 1000)]
    );

    res.json({
      success: true,
      data: history.rows
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'FETCH_SECURITY_HISTORY_ERROR',
      message: 'Error fetching user security history'
    });
  }
});

// ==================== HELPER FUNCTIONS ====================
function getPeriodStart(period) {
  const now = new Date();
  switch (period) {
    case 'today':
      return new Date(now.getFullYear(), now.getMonth(), now.getDate());
    case 'week':
      return new Date(now.getFullYear(), now.getMonth(), now.getDate() - 7);
    case 'month':
      return new Date(now.getFullYear(), now.getMonth() - 1, now.getDate());
    default:
      return new Date(now.getFullYear(), now.getMonth(), now.getDate());
  }
}

// ==================== SYSTEM INITIALIZATION ====================
async function initializeSystem() {
  try {
    await initializeSecurityTables();
    console.log('✅ Security system initialized successfully');
    
    // Insert default security stations if none exist
    const stationCount = await pool.query('SELECT COUNT(*) FROM security_stations');
    if (parseInt(stationCount.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO security_stations (station_id, station_name, location, station_type, building_type, gender_restriction) VALUES
        ('GATE_MAIN', 'Main Gate', 'University Main Entrance', 'Entrance', 'Gate', 'None'),
        ('HOSTEL_MALE_ENTRY', 'Male Hostel Entrance', 'Male Hostel Building A', 'Entrance', 'Hostel', 'Male'),
        ('HOSTEL_FEMALE_ENTRY', 'Female Hostel Entrance', 'Female Hostel Building B', 'Entrance', 'Hostel', 'Female'),
        ('LIBRARY_ENTRY', 'Library Main Entrance', 'Main Library Building', 'Entrance', 'Library', 'None'),
        ('SCIENCE_LAB_ENTRY', 'Science Lab Entrance', 'Science Building Block A', 'Entrance', 'Lab', 'None')
      `);
      console.log('✅ Default security stations created');
    }

    // Insert default curfew rules
    const curfewCount = await pool.query('SELECT COUNT(*) FROM curfew_rules');
    if (parseInt(curfewCount.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO curfew_rules (building_type, restricted_gender, start_time, end_time) VALUES
        ('Hostel', 'Male', '22:00:00', '06:00:00'),
        ('Hostel', 'Female', '22:00:00', '06:00:00')
      `);
      console.log('✅ Default curfew rules created');
    }
  } catch (error) {
    console.error('❌ System initialization failed:', error);
  }
}

// ==================== START SERVER ====================
app.listen(PORT, '0.0.0.0', async () => {
  console.log(`🚀 SmartSphere Security API running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV}`);
  console.log(`🔐 Security Level: ENTERPRISE`);
  console.log(`🎓 Egerton SmartSphere - Advanced Security System`);
  
  await initializeSystem();
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down security system gracefully...');
  await pool.end();
  process.exit(0);
});

module.exports = app;
