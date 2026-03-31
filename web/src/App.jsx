import React, { useState } from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Attackers from './pages/Attackers'
import Logs from './pages/Logs'

export default function App() {
  const [apiKey, setApiKey] = useState(localStorage.getItem('HONEYPOT_API_KEY') || '');

  if (!apiKey) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', background: 'var(--bg-main)', color: 'var(--text-main)', fontFamily: 'system-ui' }}>
        <div style={{ padding: '32px', background: 'var(--surface)', borderRadius: '12px', border: '1px solid var(--border)', width: '100%', maxWidth: '350px', textAlign: 'center', boxShadow: '0 8px 24px rgba(0,0,0,0.5)' }}>
          <h2 style={{ marginBottom: '8px', color: 'var(--text-main)' }}>🔒 Secured Sector</h2>
          <p style={{ marginBottom: '24px', color: 'var(--text-muted)' }}>Enter Management API Key</p>
          <input 
            type="password" 
            placeholder="API Key..." 
            onKeyDown={(e) => {
              if (e.key === 'Enter' && e.target.value.trim() !== '') {
                localStorage.setItem('HONEYPOT_API_KEY', e.target.value.trim());
                setApiKey(e.target.value.trim());
              }
            }}
            style={{ 
              padding: '12px', background: 'var(--bg-main)', color: 'white', 
              border: '1px solid var(--border)', borderRadius: '6px', 
              width: '100%', fontSize: '1rem', outline: 'none'
            }}
          />
          <p style={{ marginTop: '16px', fontSize: '12px', color: 'var(--text-muted)' }}>Press Enter to unlock</p>
        </div>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <div className="app-layout">
        <aside className="sidebar">
          <div className="sidebar-logo">
            <h1>🍯 Honeypot</h1>
            <span>Management Console</span>
          </div>
          <ul className="sidebar-nav">
            <li>
              <NavLink to="/" className={({ isActive }) => isActive ? 'active' : ''}>
                <span className="nav-icon">📊</span> Dashboard
              </NavLink>
            </li>
            <li>
              <NavLink to="/attackers" className={({ isActive }) => isActive ? 'active' : ''}>
                <span className="nav-icon">🎯</span> Attackers
              </NavLink>
            </li>
            <li>
              <NavLink to="/logs" className={({ isActive }) => isActive ? 'active' : ''}>
                <span className="nav-icon">📜</span> Logs
              </NavLink>
            </li>
          </ul>
          <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border)' }}>
            <div className="live-indicator">LIVE</div>
          </div>
        </aside>

        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/attackers" element={<Attackers />} />
            <Route path="/logs" element={<Logs />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
