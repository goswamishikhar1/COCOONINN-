
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// PostgreSQL connection: use Supabase's transaction pooler URI.
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL environment variable is missing');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 1,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 10000
});

// Check the database connection without creating tables at startup.
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      success: true,
      message: 'COCOONInn API and database are running',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Database health check failed:', error.message);
    res.status(503).json({
      success: false,
      message: 'Database connection failed'
    });
  }
});

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { fullName, email, mobile, password } = req.body;

    if (
      typeof fullName !== 'string' ||
      typeof email !== 'string' ||
      typeof mobile !== 'string' ||
      typeof password !== 'string' ||
      !fullName.trim() ||
      !email.trim() ||
      !mobile.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    const cleanName = fullName.trim();
    const cleanEmail = email.trim().toLowerCase();
    const cleanMobile = mobile.replace(/\D/g, '');

    if (cleanName.length > 150 || cleanEmail.length > 254) {
      return res.status(400).json({
        success: false,
        message: 'Name or email is too long'
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    if (!/^\d{10}$/.test(cleanMobile)) {
      return res.status(400).json({
        success: false,
        message: 'Enter a valid 10-digit mobile number'
      });
    }

    if (password.length < 6 || password.length > 72) {
      return res.status(400).json({
        success: false,
        message: 'Password must be between 6 and 72 characters'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO public.users (full_name, email, mobile, password)
       VALUES ($1, $2, $3, $4)
       RETURNING id, full_name AS "fullName", email, mobile,
                 "createdAt" AS "createdAt"`,
      [cleanName, cleanEmail, cleanMobile, hashedPassword]
    );

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: result.rows[0]
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    console.error('Signup error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to complete signup'
    });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const result = await pool.query(
      `SELECT id, full_name, email, mobile, password, "createdAt"
       FROM public.users
       WHERE email = $1
       LIMIT 1`,
      [cleanEmail]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        mobile: user.mobile,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Login error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to complete login'
    });
  }
});

// Vercel's Express integration uses this exported app.
module.exports = app;

// Allow local development with: npm start
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`COCOONInn API running on port ${PORT}`);
  });
}
