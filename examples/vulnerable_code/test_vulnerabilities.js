/**
 * Example file with intentional security vulnerabilities for testing SAST scanning.
 *
 * DO NOT use this code in production!
 * This file is for testing and demonstration purposes only.
 */

const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');
const app = express();

// ============================================================================
// VULNERABILITY 1: SQL Injection
// ============================================================================

function getUserVulnerable(userId) {
    // VULNERABLE: SQL injection via string concatenation
    // CWE-89: Improper Neutralization of Special Elements used in an SQL Command
    const query = `SELECT * FROM users WHERE id = ${userId}`; // VULNERABLE
    return db.execute(query);
}

function getUserSafe(userId) {
    // SAFE: Using parameterized query
    const query = 'SELECT * FROM users WHERE id = ?';
    return db.execute(query, [userId]);
}

// ============================================================================
// VULNERABILITY 2: Command Injection
// ============================================================================

function pingHostVulnerable(hostname) {
    // VULNERABLE: Command injection via exec()
    // CWE-77: Improper Neutralization of Special Elements used in an OS Command
    exec(`ping -c 4 ${hostname}`, (error, stdout) => { // VULNERABLE
        console.log(stdout);
    });
}

function pingHostSafe(hostname) {
    // SAFE: Using spawn with array arguments (no shell interpretation)
    const { spawn } = require('child_process');
    spawn('ping', ['ping', '-c', '4', hostname]);
}

// ============================================================================
// VULNERABILITY 3: Hardcoded Secrets
// ============================================================================

// VULNERABLE: Hardcoded API key
const API_KEY = 'test_api_key_replace_with_real_key_do_not_commit'; // VULNERABLE

// VULNERABLE: Hardcoded database password
const DB_PASSWORD = 'test_password_replace_with_real_password'; // VULNERABLE

function getApiConfigSafe() {
    // SAFE: Load from environment variables
    return {
        apiKey: process.env.API_KEY,
        dbPassword: process.env.DB_PASSWORD
    };
}

// ============================================================================
// VULNERABILITY 4: Cross-Site Scripting (XSS)
// ============================================================================

app.get('/greeting', (req, res) => {
    const username = req.query.username;
    // VULNERABLE: Reflected XSS via unsanitized user input
    // CWE-79: Improper Neutralization of Input During Web Page Generation
    res.send(`<h1>Hello, ${username}!</h1>`); // VULNERABLE
});

app.get('/greeting-safe', (req, res) => {
    const username = req.query.username;
    // SAFE: Use template with auto-escaping or sanitize input
    const sanitizeHtml = require('sanitize-html');
    const clean = sanitizeHtml(username);
    res.send(`<h1>Hello, ${clean}!</h1>`);
});

// ============================================================================
// VULNERABILITY 5: eval() Usage - Code Injection
// ============================================================================

function calculateVulnerable(expression) {
    // VULNERABLE: Using eval() with user input
    // CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
    return eval(expression); // VULNERABLE
}

function calculateSafe(expression) {
    // SAFE: Use a proper expression parser
    const { Parser } = require('expr-eval');
    const parser = new Parser();
    return parser.parse(expression).value;
}

// ============================================================================
// VULNERABILITY 6: Weak Cryptography
// ============================================================================

function hashPasswordVulnerable(password) {
    // VULNERABLE: Using MD5 for password hashing
    // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
    return crypto.createHash('md5').update(password).digest('hex'); // VULNERABLE
}

function hashPasswordSafe(password) {
    // SAFE: Using bcrypt for password hashing
    const bcrypt = require('bcrypt');
    const salt = bcrypt.genSaltSync(10);
    return bcrypt.hashSync(password, salt);
}

// ============================================================================
// VULNERABILITY 7: Insecure Random Number Generation
// ============================================================================

function generateTokenVulnerable() {
    // VULNERABLE: Using Math.random() for security-sensitive tokens
    // CWE-338: Use of Cryptographically Weak PRNG
    let token = '';
    const chars = 'abcdef0123456789';
    for (let i = 0; i < 32; i++) {
        token += chars[Math.floor(Math.random() * chars.length)]; // VULNERABLE
    }
    return token;
}

function generateTokenSafe() {
    // SAFE: Using crypto.randomBytes() for cryptographic security
    return crypto.randomBytes(32).toString('hex');
}

// ============================================================================
// VULNERABILITY 8: Path Traversal
// ============================================================================

const fs = require('fs');

function readFileVulnerable(filename) {
    // VULNERABLE: Path traversal via unsanitized filename
    // CWE-22: Improper Limitation of a Pathname to a Restricted Directory
    const path = `/var/app/files/${filename}`; // VULNERABLE
    return fs.readFileSync(path, 'utf8');
}

function readFileSafe(filename) {
    // SAFE: Validate and sanitize filename
    const path = require('path');

    // Remove any path components
    const sanitized = filename.replace(/[^a-zA-Z0-9._-]/g, '');

    // Construct full path
    const fullPath = path.join('/var/app/files', sanitized);

    // Ensure result is within allowed directory
    const resolvedPath = path.resolve(fullPath);
    if (!resolvedPath.startsWith('/var/app/files/')) {
        throw new Error('Access denied');
    }

    return fs.readFileSync(resolvedPath, 'utf8');
}

// ============================================================================
// VULNERABILITY 9: Insecure Direct Object Reference (IDOR)
// ============================================================================

app.get('/orders/:orderId', (req, res) => {
    const orderId = req.params.orderId;
    const order = db.getOrder(orderId);
    // VULNERABLE: No authorization check - any user can access any order
    // CWE-639: Insecure Direct Object Reference
    res.json(order); // VULNERABLE
});

app.get('/orders-safe/:orderId', (req, res) => {
    const orderId = req.params.orderId;
    const order = db.getOrder(orderId);

    // SAFE: Check that user owns the order
    if (order.userId !== req.user.id) {
        return res.status(403).json({ error: 'Access denied' });
    }

    res.json(order);
});

// ============================================================================
// VULNERABILITY 10: Regular Expression Denial of Service (ReDoS)
// ============================================================================

function validateEmailVulnerable(email) {
    // VULNERABLE: Catastrophic backtracking regex
    // CWE-1333: Inefficient Regular Expression Complexity
    const regex = /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*@(([a-zA-Z0-9]-)+(([a-zA-Z0-9])+))$/; // VULNERABLE
    return regex.test(email);
}

function validateEmailSafe(email) {
    // SAFE: Use a well-tested email validation library or simple regex
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

// ============================================================================
// VULNERABILITY 11: Sensitive Data in URL
// ============================================================================

app.get('/reset-password', (req, res) => {
    const token = req.query.token;
    // VULNERABLE: Sensitive token passed in URL (will be logged)
    // CWE-598: Use of GET Request Method With Sensitive Query Strings
    return res.send(`Reset password with token: ${token}`); // VULNERABLE
});

app.post('/reset-password', (req, res) => {
    const token = req.body.token; // SAFE: Use POST body for sensitive data
    // Validate token and reset password
    return res.send('Password reset email sent');
});

// ============================================================================
// VULNERABILITY 12: Missing Rate Limiting
// ============================================================================

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // VULNERABLE: No rate limiting - vulnerable to brute force attacks
    // CWE-307: Improper Restriction of Excessive Authentication Attempts
    const user = authenticateUser(username, password);
    if (user) {
        res.json({ token: user.token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// SAFE: Use rate limiting middleware
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many login attempts'
});

app.post('/login-safe', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    const user = authenticateUser(username, password);
    if (user) {
        res.json({ token: user.token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

if (require.main === module) {
    console.log('This file contains intentional vulnerabilities for testing SAST scanning');
    console.log('Do NOT use in production!');
}

module.exports = app;
