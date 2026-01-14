import { useState, useEffect } from 'react'
import { getAnomalies } from '../services/api'
import './AnomalyList.css'

interface Anomaly {
  log_id: string
  risk_score: number
  risk_level: string
  reasons: string[]
  recommended_action: string
  timestamp: string
  model_scores: {
    isolation_forest: number
    dbscan: number
    gmm: number
  }
}

function AnomalyList() {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null)
  const [minRiskScore, setMinRiskScore] = useState(0.6)

  useEffect(() => {
    loadAnomalies()
    const interval = setInterval(loadAnomalies, 60000) // Refresh every 60s
    return () => clearInterval(interval)
  }, [minRiskScore])

  const loadAnomalies = async () => {
    try {
      setLoading(true)
      const data = await getAnomalies({ 
        limit: 50, 
        min_risk_score: minRiskScore,
        hours: 24 
      })
      setAnomalies(data.anomalies)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load anomalies')
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (level: string) => {
    const colors: Record<string, string> = {
      critical: 'critical',
      high: 'danger',
      medium: 'warning',
      low: 'success'
    }
    return colors[level.toLowerCase()] || 'secondary'
  }

  const getActionIcon = (action: string) => {
    const icons: Record<string, string> = {
      BLOCK_IP: '🚫',
      REQUIRE_MFA: '🔐',
      ALERT_ADMIN: '📢',
      MONITOR: '👁️',
      NO_ACTION: '✅'
    }
    return icons[action] || '❓'
  }

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString()
  }

  if (loading && anomalies.length === 0) {
    return (
      <section className="anomaly-list">
        <h2 className="section-title">Recent Anomalies</h2>
        <div className="loading">Loading anomalies...</div>
      </section>
    )
  }

  return (
    <section className="anomaly-list">
      <div className="list-header">
        <h2 className="section-title">Recent Anomalies (24h)</h2>
        <div className="filter-controls">
          <label>
            Min Risk Score:
            <select 
              value={minRiskScore} 
              onChange={(e) => setMinRiskScore(Number(e.target.value))}
              className="filter-select"
            >
              <option value={0.4}>0.4 (Low+)</option>
              <option value={0.6}>0.6 (Medium+)</option>
              <option value={0.8}>0.8 (High+)</option>
              <option value={0.9}>0.9 (Critical)</option>
            </select>
          </label>
          <button onClick={loadAnomalies} className="refresh-btn">
            🔄 Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="error-message">
          <span>⚠️ {error}</span>
          <button onClick={loadAnomalies}>Retry</button>
        </div>
      )}

      {anomalies.length === 0 ? (
        <div className="empty-state">
          <span>✅</span>
          <p>No anomalies detected in the last 24 hours</p>
          <p className="empty-subtitle">Try lowering the risk score filter</p>
        </div>
      ) : (
        <div className="anomalies-grid">
          {anomalies.map((anomaly) => (
            <div 
              key={anomaly.log_id} 
              className={`anomaly-card ${getRiskColor(anomaly.risk_level)}`}
              onClick={() => setSelectedAnomaly(anomaly)}
            >
              <div className="anomaly-header">
                <span className={`risk-badge ${getRiskColor(anomaly.risk_level)}`}>
                  {anomaly.risk_level.toUpperCase()}
                </span>
                <span className="risk-score">{anomaly.risk_score.toFixed(3)}</span>
              </div>

              <div className="anomaly-reasons">
                {anomaly.reasons.slice(0, 2).map((reason, idx) => (
                  <div key={idx} className="reason-item">
                    <span className="reason-bullet">•</span>
                    <span>{reason}</span>
                  </div>
                ))}
                {anomaly.reasons.length > 2 && (
                  <div className="reason-more">
                    +{anomaly.reasons.length - 2} more reasons
                  </div>
                )}
              </div>

              <div className="anomaly-footer">
                <span className="action-badge">
                  {getActionIcon(anomaly.recommended_action)} {anomaly.recommended_action}
                </span>
                <span className="timestamp">{formatTimestamp(anomaly.timestamp)}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {selectedAnomaly && (
        <div className="modal-overlay" onClick={() => setSelectedAnomaly(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Anomaly Details</h3>
              <button onClick={() => setSelectedAnomaly(null)} className="modal-close">
                ✕
              </button>
            </div>

            <div className="modal-body">
              <div className="detail-group">
                <label>Log ID</label>
                <code>{selectedAnomaly.log_id}</code>
              </div>

              <div className="detail-group">
                <label>Risk Score</label>
                <div className="score-details">
                  <div>Overall: <strong>{selectedAnomaly.risk_score.toFixed(3)}</strong></div>
                  <div>Isolation Forest: {selectedAnomaly.model_scores.isolation_forest.toFixed(3)}</div>
                  <div>DBSCAN: {selectedAnomaly.model_scores.dbscan.toFixed(3)}</div>
                  <div>GMM: {selectedAnomaly.model_scores.gmm.toFixed(3)}</div>
                </div>
              </div>

              <div className="detail-group">
                <label>Reasons for Detection</label>
                <ul className="reasons-list">
                  {selectedAnomaly.reasons.map((reason, idx) => (
                    <li key={idx}>{reason}</li>
                  ))}
                </ul>
              </div>

              <div className="detail-group">
                <label>Recommended Action</label>
                <div className="action-detail">
                  {getActionIcon(selectedAnomaly.recommended_action)} {selectedAnomaly.recommended_action}
                </div>
              </div>

              <div className="detail-group">
                <label>Timestamp</label>
                <div>{formatTimestamp(selectedAnomaly.timestamp)}</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

export default AnomalyList
