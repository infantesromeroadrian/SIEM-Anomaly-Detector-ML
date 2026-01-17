import { useState } from 'react'
import './MLFlowDiagram.css'

interface StepInfo {
  title: string
  description: string
  details: string[]
  icon: string
}

const steps: Record<string, StepInfo> = {
  input: {
    title: 'Log Input',
    description: 'Raw security log arrives',
    details: [
      'Sources: Syslog, Nginx, SSH Auth, Firewall',
      'Formats: RFC 3164/5424, JSON, Plain text',
      'Ingestion: HTTP POST, UDP, File watch',
    ],
    icon: '📥',
  },
  parser: {
    title: 'Parser',
    description: 'Extract structured data',
    details: [
      'Identify log type (syslog, nginx, auth, firewall)',
      'Extract: timestamp, IP, user, event_type',
      'Parse metadata: status_code, endpoint, port',
      'Handle multiple formats automatically',
    ],
    icon: '🔍',
  },
  features: {
    title: 'Feature Engineering',
    description: 'Calculate 21 features in real-time',
    details: [
      'Temporal: hour_of_day, day_of_week, is_weekend',
      'Frequency: login_attempts_per_min, unique_ips',
      'Rates: failed_auth_rate, error_rate_5xx',
      'Geographic: distance_km, is_known_country',
      'Behavioral: bytes_transferred, session_duration',
      'Context: is_privileged_user, is_sensitive_endpoint',
    ],
    icon: '⚙️',
  },
  isolation_forest: {
    title: 'Isolation Forest',
    description: 'Detects outliers (50% weight)',
    details: [
      'Algorithm: Randomly isolates data points',
      'Best for: External attacks, port scans, brute force',
      'Fast: O(n) complexity, no scaling needed',
      'Output: Anomaly score 0.0-1.0',
    ],
    icon: '🌲',
  },
  dbscan: {
    title: 'DBSCAN',
    description: 'Finds density-based clusters (30% weight)',
    details: [
      'Algorithm: Density-Based Spatial Clustering',
      'Best for: Insider threats, coordinated attacks',
      'Identifies: Irregular patterns, DDoS clusters',
      'Output: Cluster membership + anomaly score',
    ],
    icon: '🔵',
  },
  gmm: {
    title: 'Gaussian Mixture Model',
    description: 'Statistical probability model (20% weight)',
    details: [
      'Algorithm: Probabilistic generative model',
      'Best for: Statistical anomalies, rare events',
      'Provides: Confidence scores, soft clustering',
      'Output: Log-likelihood probability',
    ],
    icon: '📊',
  },
  aggregation: {
    title: 'Score Aggregation',
    description: 'Weighted ensemble voting',
    details: [
      'Formula: 0.5×IF + 0.3×DBSCAN + 0.2×GMM',
      'IF prioritized: Fast detection of obvious outliers',
      'DBSCAN secondary: Complex attack patterns',
      'GMM final: Statistical confidence',
      'Threshold: >0.8 = HIGH, >0.6 = MEDIUM',
    ],
    icon: '⚖️',
  },
  decision: {
    title: 'Risk Decision',
    description: 'Final classification',
    details: [
      'HIGH (>0.8): Block IP, Alert SOC team',
      'MEDIUM (0.6-0.8): Require MFA, Monitor closely',
      'LOW (0.4-0.6): Log only, Passive monitoring',
      'NORMAL (<0.4): No action required',
      'Store in PostgreSQL for analysis',
    ],
    icon: '⚠️',
  },
}

const MLFlowDiagram = () => {
  const [activeStep, setActiveStep] = useState<string | null>(null)

  return (
    <div className="ml-flow-diagram">
      <h3>🔄 ML Prediction Pipeline (Interactive)</h3>
      <p className="diagram-subtitle">Click on any step to see details</p>

      <div className="pipeline-flow">
        {/* Step 1: Input */}
        <div
          className={`flow-step ${activeStep === 'input' ? 'active' : ''}`}
          onClick={() => setActiveStep(activeStep === 'input' ? null : 'input')}
        >
          <div className="step-icon">{steps.input.icon}</div>
          <div className="step-title">{steps.input.title}</div>
          <div className="step-desc">{steps.input.description}</div>
        </div>

        <div className="flow-arrow">↓</div>

        {/* Step 2: Parser */}
        <div
          className={`flow-step ${activeStep === 'parser' ? 'active' : ''}`}
          onClick={() => setActiveStep(activeStep === 'parser' ? null : 'parser')}
        >
          <div className="step-icon">{steps.parser.icon}</div>
          <div className="step-title">{steps.parser.title}</div>
          <div className="step-desc">{steps.parser.description}</div>
        </div>

        <div className="flow-arrow">↓</div>

        {/* Step 3: Feature Engineering */}
        <div
          className={`flow-step ${activeStep === 'features' ? 'active' : ''}`}
          onClick={() => setActiveStep(activeStep === 'features' ? null : 'features')}
        >
          <div className="step-icon">{steps.features.icon}</div>
          <div className="step-title">{steps.features.title}</div>
          <div className="step-desc">{steps.features.description}</div>
        </div>

        <div className="flow-arrow">↓</div>

        {/* Step 4: Ensemble Models (3 parallel) */}
        <div className="ensemble-container">
          <div className="ensemble-label">Ensemble (Parallel Execution)</div>
          <div className="ensemble-models">
            <div
              className={`flow-step model-step if ${activeStep === 'isolation_forest' ? 'active' : ''}`}
              onClick={() =>
                setActiveStep(activeStep === 'isolation_forest' ? null : 'isolation_forest')
              }
            >
              <div className="step-icon">{steps.isolation_forest.icon}</div>
              <div className="step-title">{steps.isolation_forest.title}</div>
              <div className="step-desc">{steps.isolation_forest.description}</div>
            </div>

            <div
              className={`flow-step model-step dbscan ${activeStep === 'dbscan' ? 'active' : ''}`}
              onClick={() => setActiveStep(activeStep === 'dbscan' ? null : 'dbscan')}
            >
              <div className="step-icon">{steps.dbscan.icon}</div>
              <div className="step-title">{steps.dbscan.title}</div>
              <div className="step-desc">{steps.dbscan.description}</div>
            </div>

            <div
              className={`flow-step model-step gmm ${activeStep === 'gmm' ? 'active' : ''}`}
              onClick={() => setActiveStep(activeStep === 'gmm' ? null : 'gmm')}
            >
              <div className="step-icon">{steps.gmm.icon}</div>
              <div className="step-title">{steps.gmm.title}</div>
              <div className="step-desc">{steps.gmm.description}</div>
            </div>
          </div>
        </div>

        <div className="flow-arrow">↓</div>

        {/* Step 5: Aggregation */}
        <div
          className={`flow-step ${activeStep === 'aggregation' ? 'active' : ''}`}
          onClick={() =>
            setActiveStep(activeStep === 'aggregation' ? null : 'aggregation')
          }
        >
          <div className="step-icon">{steps.aggregation.icon}</div>
          <div className="step-title">{steps.aggregation.title}</div>
          <div className="step-desc">{steps.aggregation.description}</div>
        </div>

        <div className="flow-arrow">↓</div>

        {/* Step 6: Decision */}
        <div
          className={`flow-step decision-step ${activeStep === 'decision' ? 'active' : ''}`}
          onClick={() => setActiveStep(activeStep === 'decision' ? null : 'decision')}
        >
          <div className="step-icon">{steps.decision.icon}</div>
          <div className="step-title">{steps.decision.title}</div>
          <div className="step-desc">{steps.decision.description}</div>
        </div>
      </div>

      {/* Detail Panel */}
      {activeStep && (
        <div className="detail-panel">
          <div className="detail-header">
            <span className="detail-icon">{steps[activeStep].icon}</span>
            <h4>{steps[activeStep].title}</h4>
            <button
              className="close-btn"
              onClick={() => setActiveStep(null)}
              aria-label="Close details"
            >
              ✕
            </button>
          </div>
          <p className="detail-description">{steps[activeStep].description}</p>
          <ul className="detail-list">
            {steps[activeStep].details.map((detail, idx) => (
              <li key={idx}>{detail}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Performance Metrics */}
      <div className="pipeline-metrics">
        <div className="metric-item">
          <span className="metric-label">Avg Latency:</span>
          <span className="metric-value">~8ms</span>
        </div>
        <div className="metric-item">
          <span className="metric-label">Throughput:</span>
          <span className="metric-value">~125 logs/sec</span>
        </div>
        <div className="metric-item">
          <span className="metric-label">Features:</span>
          <span className="metric-value">21 real-time</span>
        </div>
        <div className="metric-item">
          <span className="metric-label">Models:</span>
          <span className="metric-value">3 parallel</span>
        </div>
      </div>
    </div>
  )
}

export default MLFlowDiagram
