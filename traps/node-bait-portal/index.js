const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');

const app = express();
const HTTP_PORT = process.env.HTTP_PORT || 8080;
const HTTPS_PORT = process.env.HTTPS_PORT || 8443;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const MGMT_API = process.env.MGMT_API_URL || 'http://mgmt:9090';
const API_KEY = process.env.HONEYPOT_API_KEY || 'hk_live_8f92bd8c734a6eef9012';

// Logger utility to send data to Management API
async function logToMgmt(req, protocol, eventType, data) {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    const session_id = `${protocol}_bait_${crypto.createHash('md5').update(ip).digest('hex').substring(0, 16)}`;
    
    try {
        await axios.post(`${MGMT_API}/api/internal/ingest/event`, {
            session_id: session_id,
            ip: ip,
            port: req.connection.remotePort || 0,
            protocol: protocol,
            event_type: eventType,
            data: data
        }, {
            headers: { 'X-API-Key': API_KEY }
        });
    } catch (e) {
        console.error(`Failed to log to mgmt API: ${e.message}`);
    }
}

// Middleware to capture all requests
app.use((req, res, next) => {
    const protocol = req.secure ? 'https' : 'http';
    logToMgmt(req, protocol, 'http_request', `${req.method} ${req.url} HTTP/${req.httpVersion}`);
    
    // Log user agents or interesting headers
    if (req.headers['user-agent']) {
        logToMgmt(req, protocol, 'http_header', `User-Agent: ${req.headers['user-agent']}`);
    }
    
    next();
});

// Serve the realistic Synergy Corp login page
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Synergy Corp - Enterprise Portal</title>
<style>
  * { box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
  body { margin: 0; padding: 0; background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); height: 100vh; display: flex; justify-content: center; align-items: center; }
  .login-container { background-color: #ffffff; width: 100%; max-width: 400px; padding: 40px; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); text-align: center; }
  .logo { font-size: 28px; font-weight: bold; color: #1e3c72; margin-bottom: 10px; }
  .subtitle { color: #666; font-size: 14px; margin-bottom: 30px; }
  .input-group { margin-bottom: 20px; text-align: left; }
  .input-group label { display: block; margin-bottom: 8px; color: #333; font-weight: 500; font-size: 14px; }
  .input-group input { width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; transition: border-color 0.3s; }
  .input-group input:focus { outline: none; border-color: #1e3c72; }
  .btn-login { width: 100%; padding: 12px; background-color: #1e3c72; color: #fff; border: none; border-radius: 4px; font-size: 16px; font-weight: bold; cursor: pointer; transition: background-color 0.3s; }
  .btn-login:hover { background-color: #2a5298; }
  .links { margin-top: 20px; font-size: 13px; color: #666; }
  .links a { color: #1e3c72; text-decoration: none; }
  .links a:hover { text-decoration: underline; }
</style>
</head>
<body>
  <div class="login-container">
    <div class="logo">Synergy Corp</div>
    <div class="subtitle">Enterprise Single Sign-On</div>
    <form action="/login" method="POST">
      <div class="input-group">
        <label for="username">Employee ID / Email</label>
        <input type="text" id="username" name="username" placeholder="e.g. jdoe@synergy.corp" required>
      </div>
      <div class="input-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit" class="btn-login">Secure Login</button>
    </form>
    <div class="links">
      <p><a href="/?page=forgot-password">Forgot Password?</a></p>
      <p>Need help? Contact <a href="mailto:it-support@synergy.corp">IT Support</a></p>
      <p style="margin-top: 30px; font-size: 11px; color: #aaa;">&copy; 2024 Synergy Corporation. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`);
});

// Handle Login Form POST
app.post('/login', (req, res) => {
    const protocol = req.secure ? 'https' : 'http';
    const { username, password } = req.body;
    
    // Log the captured credentials
    if (username || password) {
        logToMgmt(req, protocol, 'credentials', `username:${username}|password:${password}`);
    }

    // Redirect to the dashboard
    res.redirect('/dashboard');
});

// The simulated Dashboard
app.get('/dashboard', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Synergy Corp - Employee Dashboard</title>
<style>
  * { box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
  body { margin: 0; padding: 0; background-color: #f4f6f9; color: #333; }
  .header { background-color: #1e3c72; color: #fff; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
  .header h1 { margin: 0; font-size: 24px; }
  .user-info { font-size: 14px; }
  .container { max-width: 1000px; margin: 40px auto; padding: 20px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
  .card { background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); transition: transform 0.2s; border-top: 4px solid #1e3c72; }
  .card:hover { transform: translateY(-5px); }
  .card h3 { margin-top: 0; color: #1e3c72; border-bottom: 1px solid #eee; padding-bottom: 10px; }
  .card p { color: #666; font-size: 14px; line-height: 1.5; }
  .card a { display: inline-block; margin-top: 15px; padding: 10px 20px; background-color: #1e3c72; color: #fff; text-decoration: none; border-radius: 4px; font-size: 14px; font-weight: bold; }
  .card a:hover { background-color: #2a5298; }
  .alert { background-color: #ffebee; color: #c62828; padding: 15px; border-radius: 4px; margin-bottom: 30px; border-left: 4px solid #c62828; }
</style>
</head>
<body>
  <div class="header">
    <h1>Synergy Corp Intranet</h1>
    <div class="user-info">Logged in as User | <a href="/" style="color: #a9c2f0; text-decoration: none;">Logout</a></div>
  </div>
  <div class="container">
    <div class="alert">
      <strong>Security Notice:</strong> The legacy employee database is scheduled for migration next month. Please ensure all queries are completed before the maintenance window.
    </div>
    <div class="grid">
      <div class="card">
        <h3>Internal Developer Tools</h3>
        <p>Access the internal Node.js debugging and deployment pipeline. (Authorized engineers only).</p>
        <a href="http://${req.hostname}:8081" target="_blank">Launch Tools</a>
      </div>
      <div class="card">
        <h3>Legacy Document Viewer</h3>
        <p>Browse archived company policies and HR documents via the old PHP file viewer.</p>
        <a href="http://${req.hostname}:8083" target="_blank">Open Viewer</a>
      </div>
      <div class="card">
        <h3>Employee Database (v1)</h3>
        <p>Search the legacy employee directory. Note: This system is deprecated and pending replacement.</p>
        <a href="http://${req.hostname}:8084" target="_blank">Search Directory</a>
      </div>
      <div class="card">
        <h3>API Testing Endpoint</h3>
        <p>Internal SSRF testing and webhook validation service. Use with caution.</p>
        <a href="http://${req.hostname}:8082" target="_blank">Access API</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// Fallback for random paths
app.use((req, res) => {
    res.status(404).send('404 Not Found');
});

// Start HTTP Server
http.createServer(app).listen(HTTP_PORT, () => {
    console.log(`HTTP Bait Portal listening on port ${HTTP_PORT}`);
});

// Start HTTPS Server
const options = {
    key: fs.readFileSync('./certs/server.key'),
    cert: fs.readFileSync('./certs/server.cert')
};

https.createServer(options, app).listen(HTTPS_PORT, () => {
    console.log(`HTTPS Bait Portal listening on port ${HTTPS_PORT}`);
});