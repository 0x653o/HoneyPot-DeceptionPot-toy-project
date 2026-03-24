import React, { useState, useEffect } from 'react'
import { fetchAttackers } from '../api'

export default function Attackers() {
  const [data, setData] = useState(null)
  const [page, setPage] = useState(1)
  const [sortBy, setSortBy] = useState('count')
  const [protocolFilter, setProtocolFilter] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadData() }, [page, sortBy, protocolFilter])

  async function loadData() {
    setLoading(true)
    try {
      const result = await fetchAttackers(page, 20, sortBy, protocolFilter || null)
      setData(result)
    } catch (e) {
      console.error(e)
    }
    setLoading(false)
  }

  const totalPages = data ? Math.ceil(data.total / data.per_page) : 0

  return (
    <div>
      <div className="page-header">
        <h2>Attackers</h2>
        <p>IP addresses that connected to the honeypot</p>
      </div>

      {/* Filters */}
      <div className="card" style={{ marginBottom: 24, display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
        <div>
          <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Sort by</label>
          <select value={sortBy} onChange={e => { setSortBy(e.target.value); setPage(1) }}
            style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 8, padding: '8px 12px', color: 'var(--text-primary)', fontSize: 14 }}>
            <option value="count">Connection Count</option>
            <option value="recent">Most Recent</option>
          </select>
        </div>
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
        <div style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 13 }}>
          {data?.total || 0} total attackers
        </div>
      </div>

      {/* Table */}
      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Connections</th>
                <th>Protocols</th>
                <th>Credentials</th>
                <th>First Seen</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6}><div className="loading"><div className="spinner" /> Loading...</div></td></tr>
              ) : data?.attackers?.length ? (
                data.attackers.map(attacker => (
                  <tr key={attacker.ip}>
                    <td><span className="ip-badge">{attacker.ip}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{attacker.connection_count}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {attacker.protocols?.map(p => (
                          <span key={p} className={`protocol-badge ${p.toLowerCase()}`}>{p.toUpperCase()}</span>
                        ))}
                      </div>
                    </td>
                    <td>
                      {attacker.credential_count > 0 && (
                        <span style={{ color: 'var(--accent-amber)', fontWeight: 600 }}>{attacker.credential_count}</span>
                      )}
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{attacker.first_seen}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{attacker.last_seen}</td>
                  </tr>
                ))
              ) : (
                <tr><td colSpan={6}><div className="empty-state"><p>No attackers found</p></div></td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'center', gap: 8, padding: '16px 0', marginTop: 8 }}>
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
      </div>
    </div>
  )
}
