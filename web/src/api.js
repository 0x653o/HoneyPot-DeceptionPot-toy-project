const API_BASE = '/api';
const WS_PROTO = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const WS_BASE = `${WS_PROTO}//${window.location.host}/ws`;

export async function fetchStats() {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function fetchAttackers(page = 1, perPage = 20, sortBy = 'count', protocol = null) {
  const params = new URLSearchParams({ page, per_page: perPage, sort_by: sortBy });
  if (protocol) params.set('protocol', protocol);
  const res = await fetch(`${API_BASE}/attackers?${params}`);
  if (!res.ok) throw new Error('Failed to fetch attackers');
  return res.json();
}

export async function fetchAttackerDetail(ip) {
  const res = await fetch(`${API_BASE}/attackers/${ip}`);
  if (!res.ok) throw new Error('Failed to fetch attacker detail');
  return res.json();
}

export async function fetchLogs(page = 1, perPage = 50, protocol = null, ip = null) {
  const params = new URLSearchParams({ page, per_page: perPage });
  if (protocol) params.set('protocol', protocol);
  if (ip) params.set('ip', ip);
  const res = await fetch(`${API_BASE}/logs?${params}`);
  if (!res.ok) throw new Error('Failed to fetch logs');
  return res.json();
}

export async function fetchRecentLogs(limit = 10) {
  const res = await fetch(`${API_BASE}/logs/recent?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch recent logs');
  return res.json();
}

export async function runAnalysis(protocol = null, topN = 20, enrich = true) {
  const params = new URLSearchParams({ top_n: topN, enrich });
  if (protocol) params.set('protocol', protocol);
  const res = await fetch(`${API_BASE}/analyze?${params}`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to run analysis');
  return res.json();
}

export function createLiveFeed(onMessage) {
  let retryDelay = 1000;
  const maxDelay = 30000;

  function connect() {
    const ws = new WebSocket(`${WS_BASE}/live`);

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
