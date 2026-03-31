const express = require('express');
const { exec } = require('child_process');
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
    const safeIp = ip.replace(/[^a-zA-Z0-9]/g, '_');
    
    // Per-attacker sandbox: each IP gets its own ephemeral tmpfs via nsjail mapping if we wanted,
    // but here we just isolate them so they can't escape into the main container.
    // We bind root as RO, and give them a disposable tmpfs.
    const nsjailCmd = `nsjail -Mo --user 99999 --group 99999 -R /bin -R /lib -R /usr -R /lib64 -R /etc/resolv.conf -T /tmp -- /bin/sh -c "ping -c 1 ${host}"`;

    exec(nsjailCmd, { timeout: 3000 }, (error, stdout, stderr) => {
        res.send(`<pre>${stdout || stderr || (error ? error.message : '')}</pre>`);
    });
});

app.listen(port, () => {
    console.log(`Node RCE honeypot listening on port ${port}`);
});
