import React from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Attackers from './pages/Attackers'
import Logs from './pages/Logs'

export default function App() {
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
