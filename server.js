const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { pool, initializeDb } = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
const frontendUrl = process.env.FRONTEND_URL ? process.env.FRONTEND_URL.replace(/\/$/, "") : "";

app.use(cors({
    origin: frontendUrl,
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Initialize DB
initializeDb();

// Routes

// 1. Signup
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, phone, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: 'Please provide all required fields' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user
        const [result] = await pool.query(
            'INSERT INTO users (username, email, phone, password) VALUES (?, ?, ?, ?)',
            [username, email, phone, hashedPassword]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Username or Email already exists' });
        }
        console.error(err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// 2. Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Please provide username and password' });
        }

        const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        const user = users[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate JWT
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Determine if we should use secure cookies (HTTPS)
        const isProduction = process.env.NODE_ENV === 'production' || !frontendUrl.includes('localhost');

        // Send as HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: isProduction, // Required for cross-site cookies in most browsers
            sameSite: isProduction ? 'none' : 'lax', // 'none' + secure is required for cross-domain
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });

        res.json({
            message: 'Login successful',
            user: { username: user.username, role: user.role },
            redirectUrl: process.env.REDIRECTION_URL
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// 3. Verify Auth
app.get('/api/verify', (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ authenticated: false });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ authenticated: true, user: decoded });
    } catch (err) {
        res.status(401).json({ authenticated: false });
    }
});

// 4. Logout
app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out successfully' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;
