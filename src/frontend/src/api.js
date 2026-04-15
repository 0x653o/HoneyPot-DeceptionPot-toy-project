const API_BASE = '/api';
const WS_PROTO = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const WS_BASE = `${WS_PROTO}//${window.location.host}/ws`;

function getApiKey() {
  return localStorage.getItem('HONEYPOT_API_KEY') || '';
}

async function fetchWithAuth(url, options = {}) {
  const headers = { ...options.headers };
  const key = getApiKey();
  if (key) {
    headers['X-API-Key'] = key;
  }
  const res = await fetch(url, { ...options, headers });
  if (res.status === 401) {
    localStorage.removeItem('HONEYPOT_API_KEY');
    window.location.reload();
  }
  if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
  return res.json();
}

export async function fetchStats() {
  return fetchWithAuth(`${API_BASE}/stats`);
}

export async function fetchAttackers(page = 1, perPage = 20, sortBy = 'count', protocol = null) {
  const params = new URLSearchParams({ page, per_page: perPage, sort_by: sortBy });
  if (protocol) params.set('protocol', protocol);
  return fetchWithAuth(`${API_BASE}/attackers?${params}`);
}

export async function fetchAttackerDetail(ip) {
  return fetchWithAuth(`${API_BASE}/attackers/${ip}`);
}

export async function fetchLogs(page = 1, perPage = 50, protocol = null, ip = null) {
  const params = new URLSearchParams({ page, per_page: perPage });
  if (protocol) params.set('protocol', protocol);
  if (ip) params.set('ip', ip);
  return fetchWithAuth(`${API_BASE}/logs?${params}`);
}

export async function fetchRecentLogs(limit = 10) {
  return fetchWithAuth(`${API_BASE}/logs/recent?limit=${limit}`);
}

export async function runAnalysis(protocol = null, topN = 20, enrich = true) {
  const params = new URLSearchParams({ top_n: topN, enrich });
  if (protocol) params.set('protocol', protocol);
  return fetchWithAuth(`${API_BASE}/analyze?${params}`, { method: 'POST' });
}

export function createLiveFeed(onMessage) {
  let retryDelay = 1000;
  const maxDelay = 30000;

  function connect() {
    const key = getApiKey();
    const wsUrl = key ? `${WS_BASE}/live?token=${key}` : `${WS_BASE}/live`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      retryDelay = 1000; // Reset on success
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      onMessage(data);
    };

    ws.onerror = () => console.error('WebSocket error');

    ws.onclose = () => {
      // Exponential backoff reconnect
      setTimeout(() => {
        retryDelay = Math.min(retryDelay * 2, maxDelay);
        connect();
      }, retryDelay);
    };

    return ws;
  }

  return connect();
}
