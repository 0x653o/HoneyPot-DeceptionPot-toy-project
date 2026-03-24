import React, { useState, useEffect, useRef } from 'react'
import { fetchLogs, createLiveFeed } from '../api'

export default function Logs() {
  const [data, setData] = useState(null)
  const [page, setPage] = useState(1)
  const [protocolFilter, setProtocolFilter] = useState('')
  const [ipFilter, setIpFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [liveMode, setLiveMode] = useState(false)
  const [liveFeed, setLiveFeed] = useState([])
  const wsRef = useRef(null)
  const feedRef = useRef(null)

  useEffect(() => {
    if (!liveMode) loadData()
  }, [page, protocolFilter, ipFilter, liveMode])

  useEffect(() => {
    if (liveMode) {
      const ws = createLiveFeed((msg) => {
        setLiveFeed(prev => [msg, ...prev].slice(0, 200))
      })
      wsRef.current = ws
      return () => ws.close()
    }
  }, [liveMode])

  async function loadData() {
    setLoading(true)
    try {
      const result = await fetchLogs(page, 50, protocolFilter || null, ipFilter || null)
      setData(result)
    } catch (e) {
      console.error(e)
    }
    setLoading(false)
  }

  const totalPages = data ? Math.ceil(data.total / data.per_page) : 0
  const entries = liveMode ? liveFeed : (data?.entries || [])

  return (
    <div>
      <div className="page-header">
        <h2>Logs</h2>
        <p>Connection log entries with real-time streaming</p>
      </div>

      {/* Controls */}
      <div className="card" style={{ marginBottom: 24, display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
        <button 
          onClick={() => setLiveMode(!liveMode)}
          style={{
            background: liveMode ? 'rgba(16,185,129,0.15)' : 'var(--bg-input)',
            border: `1px solid ${liveMode ? 'var(--accent-green)' : 'var(--border)'}`,
            borderRadius: 8, padding: '8px 16px',
            color: liveMode ? 'var(--accent-green)' : 'var(--text-primary)',
            cursor: 'pointer', fontWeight: 600, fontSize: 13,
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
          {liveMode && <span className="live-indicator" style={{ margin: 0 }} />}
          {liveMode ? 'LIVE' : 'Go Live'}
        </button>

        {!liveMode && (
          <>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Protocol</label>
              <select value={protocolFilter} onChange={e => { setProtocolFilter(e.target.value); setPage(1) }}
                style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 8, padding: '8px 12px', color: 'var(--text-primary)', fontSize: 14 }}>
                <option value="">All</option>
                <option value="ssh">SSH</option>
                <option value="http">HTTP</option>
                <option value="ftp">FTP</option>
                <option value="telnet">Telnet</option>
                <option value="smtp">SMTP</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Filter IP</label>
              <input value={ipFilter} onChange={e => setIpFilter(e.target.value)} placeholder="e.g. 192.168.1.1"
                style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 8, padding: '8px 12px', color: 'var(--text-primary)', fontSize: 14, width: 200 }}
                onKeyDown={e => e.key === 'Enter' && setPage(1)} />
            </div>
          </>
        )}

        <div style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 13 }}>
          {liveMode ? `${liveFeed.length} live entries` : `${data?.total || 0} total entries`}
        </div>
      </div>

      {/* Log Table */}
      <div className="card">
        {liveMode ? (
          <div className="live-feed" ref={feedRef} style={{ maxHeight: 600 }}>
            {entries.map((entry, i) => (
              <div key={entry.id || i} className="feed-entry">
                <span className="timestamp">{entry.timestamp}</span>
                <span className={`protocol-badge ${entry.protocol?.toLowerCase()}`}>
                  {entry.protocol?.toUpperCase()}
                </span>
                <span className="ip">{entry.src_ip}</span>
                <span style={{ color: 'var(--text-muted)' }}>:{entry.src_port}</span>
              </div>
            ))}
            {!entries.length && (
              <div className="empty-state"><p>Waiting for live connections...</p></div>
            )}
          </div>
        ) : (
          <>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>Protocol</th>
                    <th>Source IP</th>
                    <th>Port</th>
                    <th>Events</th>
                    <th>Creds</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr><td colSpan={7}><div className="loading"><div className="spinner" /> Loading...</div></td></tr>
                  ) : entries.length ? (
                    entries.map(entry => (
                      <tr key={entry.id}>
                        <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: 12 }}>{entry.id}</td>
                        <td style={{ fontSize: 13, fontFamily: 'var(--font-mono)' }}>{entry.timestamp}</td>
                        <td><span className={`protocol-badge ${entry.protocol?.toLowerCase()}`}>{entry.protocol?.toUpperCase()}</span></td>
                        <td><span className="ip-badge">{entry.src_ip}</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{entry.src_port}</td>
                        <td>{entry.event_count > 0 && <span style={{ color: 'var(--accent-blue)' }}>{entry.event_count}</span>}</td>
                        <td>{entry.cred_count > 0 && <span style={{ color: 'var(--accent-amber)', fontWeight: 600 }}>🔑 {entry.cred_count}</span>}</td>
                      </tr>
                    ))
                  ) : (
                    <tr><td colSpan={7}><div className="empty-state"><p>No log entries found</p></div></td></tr>
                  )}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'center', gap: 8, padding: '16px 0' }}>
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
                  style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 14px', color: 'var(--text-primary)', cursor: 'pointer' }}>
                  ← Prev
                </button>
                <span style={{ padding: '6px 14px', color: 'var(--text-muted)', fontSize: 13 }}>
                  Page {page} of {totalPages}
                </span>
                <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
                  style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 14px', color: 'var(--text-primary)', cursor: 'pointer' }}>
                  Next →
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
