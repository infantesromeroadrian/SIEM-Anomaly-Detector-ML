import { useState, useEffect } from 'react'
import Dashboard from './components/Dashboard'
import ModelArchitecture from './components/ModelArchitecture'
import MLFlowDiagram from './components/MLFlowDiagram'
import AnomalyList from './components/AnomalyList'
import { getStats, getHealth } from './services/api'
import './App.css'

interface Stats {
  logs_analyzed_24h: number
  anomalies_detected_24h: number
  anomaly_rate: number
}

function App() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [health, setHealth] = useState<'healthy' | 'unhealthy' | 'loading'>('loading')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [])

  const loadData = async () => {
    try {
      const [statsData, healthData] = await Promise.all([
        getStats(),
        getHealth()
      ])
      
      setStats(statsData)
      setHealth(healthData.status === 'healthy' ? 'healthy' : 'unhealthy')
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data')
      setHealth('unhealthy')
    }
  }

  return (
    <div className="app">
      <header className="header">
        <div className="container">
          <div className="header-content">
            <div>
              <h1 className="title">🛡️ SIEM Anomaly Detector</h1>
              <p className="subtitle">ML-Powered Security Log Analysis</p>
            </div>
            <div className="health-indicator">
              <span className={`status-dot ${health}`}></span>
              <span className="status-text">{health === 'loading' ? 'Connecting...' : health.toUpperCase()}</span>
            </div>
          </div>
        </div>
      </header>

      <main className="main container">
        {error && (
          <div className="error-banner">
            <span>⚠️</span>
            <span>{error}</span>
            <button onClick={loadData}>Retry</button>
          </div>
        )}

        <Dashboard stats={stats} />
        <ModelArchitecture />
        <MLFlowDiagram />
        <AnomalyList />
      </main>

      <footer className="footer">
        <div className="container">
          <p>SIEM Anomaly Detector v1.0.0 | AI-RedTeam-Course | {new Date().getFullYear()}</p>
        </div>
      </footer>
    </div>
  )
}

export default App
