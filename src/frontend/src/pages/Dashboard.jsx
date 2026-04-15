import React, { useState, useEffect, useRef } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { fetchStats, fetchRecentLogs, createLiveFeed } from '../api'

const PROTOCOL_COLORS = {
  ssh: '#8b5cf6',
  http: '#3b82f6',
  ftp: '#10b981',
  telnet: '#f59e0b',
  smtp: '#06b6d4',
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [recentLogs, setRecentLogs] = useState([])
  const [liveFeed, setLiveFeed] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const wsRef = useRef(null)

  useEffect(() => {
    loadData()
    const ws = createLiveFeed((data) => {
      setLiveFeed(prev => [data, ...prev].slice(0, 50))
    })
    wsRef.current = ws
    const interval = setInterval(loadData, 10000)
    return () => {
      clearInterval(interval)
      if (wsRef.current) wsRef.current.close()
    }
  }, [])

  async function loadData() {
    try {
      const [statsData, logsData] = await Promise.all([
        fetchStats(),
        fetchRecentLogs(20),
      ])
      setStats(statsData)
      setRecentLogs(logsData)
      setLoading(false)
    } catch (e) {
      setError(e.message)
      setLoading(false)
    }
  }

  if (loading) return <div className="loading"><div className="spinner" /> Loading dashboard...</div>

  if (error) return (
    <div className="empty-state">
      <div className="icon">⚠️</div>
      <h3>Cannot connect to API</h3>
      <p>{error}</p>
      <p style={{ marginTop: 8, fontSize: 13 }}>Make sure the honeypot and API server are running.</p>
    </div>
  )

  const protocolData = stats?.protocol_breakdown
    ? Object.entries(stats.protocol_breakdown).map(([name, value]) => ({
        name: name.toUpperCase(),
        value,
        color: PROTOCOL_COLORS[name.toLowerCase()] || '#64748b',
      }))
    : []

  return (
    <div>
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>Real-time honeypot monitoring</p>
      </div>

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="card stat-card blue">
          <div className="stat-label">Total Connections</div>
          <div className="stat-value">{stats?.total_connections?.toLocaleString() || 0}</div>
        </div>
        <div className="card stat-card red">
          <div className="stat-label">Unique Attackers</div>
          <div className="stat-value">{stats?.unique_attackers?.toLocaleString() || 0}</div>
        </div>
        <div className="card stat-card amber">
          <div className="stat-label">Credentials Captured</div>
          <div className="stat-value">{stats?.total_credentials?.toLocaleString() || 0}</div>
        </div>
        <div className="card stat-card green">
          <div className="stat-label">Last 24 Hours</div>
          <div className="stat-value">{stats?.connections_last_24h?.toLocaleString() || 0}</div>
        </div>
        <div className="card stat-card purple">
          <div className="stat-label">Total Events</div>
          <div className="stat-value">{stats?.total_events?.toLocaleString() || 0}</div>
        </div>
        <div className="card stat-card cyan">
          <div className="stat-label">Protocols Active</div>
          <div className="stat-value">{protocolData.length}</div>
        </div>
      </div>

      {/* Charts */}
      <div className="charts-grid">
        <div className="card">
          <div className="chart-title">Protocol Distribution</div>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={protocolData} dataKey="value" nameKey="name" cx="50%" cy="50%"
                   innerRadius={60} outerRadius={100} strokeWidth={0}>
                {protocolData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#1a1f36', border: '1px solid #2a2f45', borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', justifyContent: 'center', gap: 16, flexWrap: 'wrap' }}>
            {protocolData.map(p => (
              <span key={p.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: p.color, display: 'inline-block' }} />
                {p.name}: {p.value}
              </span>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="chart-title">Connections by Protocol</div>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={protocolData} layout="vertical" margin={{ left: 20 }}>
              <XAxis type="number" stroke="#64748b" />
              <YAxis type="category" dataKey="name" stroke="#64748b" width={60} />
              <Tooltip contentStyle={{ background: '#1a1f36', border: '1px solid #2a2f45', borderRadius: 8 }} />
              <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                {protocolData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Live Feed */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div className="chart-title" style={{ margin: 0 }}>Live Connection Feed</div>
          <div className="live-indicator">LIVE</div>
        </div>
        <div className="live-feed">
          {(liveFeed.length > 0 ? liveFeed : recentLogs).map((entry, i) => (
            <div key={entry.id || i} className="feed-entry">
              <span className="timestamp">{entry.timestamp}</span>
              <span className={`protocol-badge ${entry.protocol?.toLowerCase()}`}>
                {entry.protocol?.toUpperCase()}
              </span>
              <span className="ip">{entry.src_ip}</span>
              <span style={{ color: 'var(--text-muted)' }}>:{entry.src_port}</span>
            </div>
          ))}
          {!liveFeed.length && !recentLogs.length && (
            <div className="empty-state">
              <p>No connections yet. Waiting for attackers...</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
