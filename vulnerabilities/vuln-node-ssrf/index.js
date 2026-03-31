const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const port = 8080;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const MGMT_API = process.env.MGMT_API_URL || 'http://mgmt:9090';
const API_KEY = process.env.HONEYPOT_API_KEY || 'hk_live_8f92bd8c734a6eef9012';

async function logAttack(req, type, data) {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    try {
        await axios.post(`${MGMT_API}/api/internal/ingest/event`, {
            session_id: `node_ssrf_${crypto.createHash('md5').update(ip).digest('hex')}`,
            ip: ip,
            port: req.connection.remotePort || 0,
            protocol: 'http-node-ssrf',
            event_type: type,
            data: data
        }, {
            headers: { 'X-API-Key': API_KEY }
        });
    } catch (e) {
        console.error("Failed to log attack to mgmt API");
    }
}

// Health check endpoint
app.get('/health', (req, res) => res.status(200).send('OK'));

// 2. Server-Side Request Forgery (SSRF)
app.get('/api/proxy', (req, res) => {
    const target = req.query.url;
    if (!target) return res.status(400).send("Missing url parameter");
    
    // Log typical internal scans
    if (target.includes('169.254.169.254') || target.includes('localhost') || target.includes('127.0.0.1')) {
        logAttack(req, "ssrf_attempt", `Target: ${target}`);
    }

    // SSRF Execution (network isolation handled via Docker internal flags)
    axios.get(target, { timeout: 2000 })
        .then(response => {
            res.send(response.data);
        })
        .catch(err => {
            res.status(500).send(`Proxy Error: ${err.message}`);
        });
});

app.listen(port, () => {
    console.log(`Node SSRF honeypot listening on port ${port}`);
});
