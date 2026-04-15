const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 8080;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const MGMT_API = process.env.MGMT_API_URL || 'http://mgmt:9090';
const API_KEY = process.env.HONEYPOT_API_KEY || 'hk_live_8f92bd8c734a6eef9012';

const SANDBOX_DIR = '/tmp/sandboxes';

function getUserTmpDir(ip) {
    const safeIp = ip.replace(/[^a-zA-Z0-9]/g, '_');
    const userTmpDir = path.join(SANDBOX_DIR, safeIp);
    if (!fs.existsSync(userTmpDir)) {
        fs.mkdirSync(userTmpDir, { recursive: true, mode: 0o777 });
    }
    return userTmpDir;
}

async function logAttack(req, type, data) {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    try {
        await axios.post(`${MGMT_API}/api/internal/ingest/event`, {
            session_id: `node_rce_${crypto.createHash('md5').update(ip).digest('hex')}`,
            ip: ip,
            port: req.connection.remotePort || 0,
            protocol: 'http-node-rce',
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

// 1. Command Injection (Enhanced RCE via shell inside nsjail)
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    if (!host) {
        return res.status(400).send("Missing host parameter");
    }
    
    if (/[;&|]/.test(host) || host.includes('`') || host.includes('$')) {
        logAttack(req, "rce_attempt", `Command payload: ${host}`);
    }

    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'default';
    const userTmpDir = getUserTmpDir(ip);
    
    // Per-attacker sandbox: each IP gets its own persistent tmpfs
    const nsjailCmd = `nsjail -Mo --user 99999 --group 99999 -R /bin -R /lib -R /usr -R /lib64 -R /etc/resolv.conf -B ${userTmpDir}:/tmp -- /bin/sh -c "ping -c 1 ${host}"`;

    exec(nsjailCmd, { timeout: 3000 }, (error, stdout, stderr) => {
        res.send(`<pre>${stdout || stderr || (error ? error.message : '')}</pre>`);
    });
});

// 2. API Generator Trap (Another RCE sink using user's tmp folder)
app.get('/api/generate', (req, res) => {
    const template = req.query.template;
    if (!template) {
        return res.status(400).send("Missing template parameter");
    }
    
    if (/[;&|]/.test(template) || template.includes('`') || template.includes('$')) {
        logAttack(req, "rce_attempt", `Template payload: ${template}`);
    }

    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'default';
    const userTmpDir = getUserTmpDir(ip);
    
    // Using API generator trap with nsjail, bind user tmp dir to /tmp
    // This looks like it's writing an API file and cat-ing it back, vulnerable to command injection
    const nsjailCmd = `nsjail -Mo --user 99999 --group 99999 -R /bin -R /lib -R /usr -R /lib64 -R /etc/resolv.conf -B ${userTmpDir}:/tmp -- /bin/sh -c "echo ${template} > /tmp/api_output.txt && cat /tmp/api_output.txt"`;

    exec(nsjailCmd, { timeout: 3000 }, (error, stdout, stderr) => {
        res.send(`<pre>${stdout || stderr || (error ? error.message : '')}</pre>`);
    });
});

app.listen(port, () => {
    console.log(`Node RCE honeypot listening on port ${port}`);
});
