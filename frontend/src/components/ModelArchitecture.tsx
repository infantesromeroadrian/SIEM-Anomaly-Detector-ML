import { useState, useEffect } from 'react'
import './ModelArchitecture.css'

interface ModelStats {
  model_version: string
}

function ModelArchitecture() {
  const [activeTab, setActiveTab] = useState<'overview' | 'architecture' | 'metrics' | 'features'>('overview')
  const [modelStats, setModelStats] = useState<ModelStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchModelStats()
  }, [])

  const fetchModelStats = async () => {
    try {
      const response = await fetch('/api/v1/stats')
      const data = await response.json()
      setModelStats({ model_version: data.model_version || 'unknown' })
      setLoading(false)
    } catch (error) {
      console.error('Failed to fetch model stats:', error)
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <section className="model-architecture">
        <h2 className="section-title">🤖 ML Model Architecture</h2>
        <div className="loading">Loading model information...</div>
      </section>
    )
  }

  return (
    <section className="model-architecture">
      <div className="architecture-header">
        <h2 className="section-title">🤖 ML Model Architecture</h2>
        <div className="model-version">
          <span className="version-badge">{modelStats?.model_version}</span>
          <span className="trained-badge">Research prototype</span>
        </div>
      </div>

      <div className="tabs">
        <button 
          className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>
        <button 
          className={`tab ${activeTab === 'architecture' ? 'active' : ''}`}
          onClick={() => setActiveTab('architecture')}
        >
          🏗️ Architecture
        </button>
        <button 
          className={`tab ${activeTab === 'metrics' ? 'active' : ''}`}
          onClick={() => setActiveTab('metrics')}
        >
          📈 Metrics
        </button>
        <button 
          className={`tab ${activeTab === 'features' ? 'active' : ''}`}
          onClick={() => setActiveTab('features')}
        >
          🔧 Features
        </button>
      </div>

      <div className="tab-content">
        {activeTab === 'overview' && <OverviewTab />}
        {activeTab === 'architecture' && <ArchitectureTab />}
        {activeTab === 'metrics' && <MetricsTab />}
        {activeTab === 'features' && <FeaturesTab />}
      </div>
    </section>
  )
}

function OverviewTab() {
  return (
    <div className="overview-tab">
      <div className="overview-grid">
        <div className="overview-card">
          <h3>🎯 Model Type</h3>
          <p className="highlight">Unsupervised Ensemble</p>
          <p className="description">
            Combines 3 anomaly detection algorithms to identify threats without 
            requiring labeled training data.
          </p>
        </div>

        <div className="overview-card">
          <h3>📏 Evaluation</h3>
          <p className="description">
            Metrics are not hardcoded in this UI. They are produced by <code>make reproduce</code>{' '}
            on a public labelled dataset and written to <code>results/metrics.json</code>{' '}
            and <code>results/report.md</code>.
          </p>
        </div>
      </div>

      <div className="why-ensemble">
        <h3>💡 Why Ensemble?</h3>
        <div className="reasons-grid">
          <div className="reason">
            <span className="reason-icon">🎯</span>
            <div>
              <h4>Better Accuracy</h4>
              <p>Multiple models catch different types of anomalies</p>
            </div>
          </div>
          <div className="reason">
            <span className="reason-icon">🛡️</span>
            <div>
              <h4>Robustness</h4>
              <p>If one model fails, others compensate</p>
            </div>
          </div>
          <div className="reason">
            <span className="reason-icon">📊</span>
            <div>
              <h4>Confidence Scoring</h4>
              <p>Agreement between models indicates confidence</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function ArchitectureTab() {
  return (
    <div className="architecture-tab">
      <h3>🏗️ Ensemble Architecture</h3>
      
      <div className="pipeline-diagram">
        <div className="pipeline-step">
          <div className="step-box input">
            <h4>📝 INPUT</h4>
            <p>Raw Security Log</p>
            <code className="log-sample">
              Jan 14 03:45:12 server sshd:<br/>
              Failed password for admin<br/>
              from 185.234.219.45
            </code>
          </div>
          <div className="arrow-down">↓</div>
        </div>

        <div className="pipeline-step">
          <div className="step-box parser">
            <h4>🔍 PARSER</h4>
            <p>Extract Structured Data</p>
            <ul>
              <li>timestamp: 2026-01-14T03:45:12Z</li>
              <li>source_ip: 185.234.219.45</li>
              <li>username: admin</li>
              <li>event_type: ssh_password_failed</li>
            </ul>
          </div>
          <div className="arrow-down">↓</div>
        </div>

        <div className="pipeline-step">
          <div className="step-box features">
            <h4>🔧 FEATURE ENGINEERING</h4>
            <p>Calculate 21 deterministic features</p>
            <div className="feature-categories">
              <span className="feature-cat">⏰ Temporal (4)</span>
              <span className="feature-cat">📊 Frequency (4)</span>
              <span className="feature-cat">📈 Rates (3)</span>
              <span className="feature-cat">🎭 Behavioral (4)</span>
              <span className="feature-cat">🔐 Context (3)</span>
            </div>
          </div>
          <div className="arrow-down">↓</div>
        </div>

        <div className="pipeline-step ensemble">
          <div className="step-box ensemble-box">
            <h4>🤖 ML ENSEMBLE</h4>
            <div className="models-grid">
              <div className="model-card if">
                <h5>Isolation Forest</h5>
                <p className="weight">Weight: 100% (default)</p>
                <p className="description">Fast outlier detection via tree isolation</p>
                <div className="model-params">
                  <span>n_estimators: 100</span>
                  <span>contamination: 0.05</span>
                </div>
              </div>

              <div className="model-card dbscan">
                <h5>DBSCAN</h5>
                <p className="weight">Weight: 0% (opt-in)</p>
                <p className="description">Density-based clustering anomaly detection</p>
                <div className="model-params">
                  <span>eps: 5.0</span>
                  <span>min_samples: 50</span>
                </div>
              </div>

              <div className="model-card gmm">
                <h5>Gaussian Mixture</h5>
                <p className="weight">Weight: 0% (opt-in)</p>
                <p className="description">Probabilistic anomaly scoring</p>
                <div className="model-params">
                  <span>n_components: 3</span>
                  <span>covariance: full</span>
                </div>
              </div>
            </div>

            <div className="aggregation">
              <p className="formula">
                <strong>Final Score =</strong> 
                <span className="formula-part">0.5 × IF</span> + 
                <span className="formula-part">0.3 × DBSCAN</span> + 
                <span className="formula-part">0.2 × GMM</span>
              </p>
              <p className="example">Example: 0.5×0.85 + 0.3×0.75 + 0.2×0.92 = <strong className="risk-high">0.834</strong></p>
            </div>
          </div>
          <div className="arrow-down">↓</div>
        </div>

        <div className="pipeline-step">
          <div className="step-box output">
            <h4>📤 OUTPUT</h4>
            <div className="output-result">
              <div className="result-main">
                <span className="anomaly-badge critical">🔴 ANOMALY DETECTED</span>
                <span className="risk-score">Risk Score: 0.834</span>
              </div>
              <div className="result-details">
                <p><strong>Risk Level:</strong> HIGH</p>
                <p><strong>Action:</strong> BLOCK_IP</p>
                <p><strong>Reasons:</strong></p>
                <ul>
                  <li>Activity at unusual hour (3 AM)</li>
                  <li>High login attempt rate (25/min)</li>
                  <li>Unknown IP address</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="algorithm-details">
        <h3>🔬 Algorithm Details</h3>
        
        <div className="algorithm-card">
          <h4>1. Isolation Forest (IF)</h4>
          <p><strong>How it works:</strong> Creates random decision trees to isolate data points. 
          Anomalies are easier to isolate (fewer splits needed) than normal points.</p>
          <p><strong>Why we use it:</strong> Fast, scales well, no assumptions about data distribution.</p>
          <p><strong>Best for:</strong> Global outliers, novel attacks.</p>
        </div>

        <div className="algorithm-card">
          <h4>2. DBSCAN (Density-Based Spatial Clustering)</h4>
          <p><strong>How it works:</strong> Groups dense regions of points. Points far from any 
          cluster are marked as outliers.</p>
          <p><strong>Why we use it:</strong> Detects local anomalies, no need to specify number of clusters.</p>
          <p><strong>Best for:</strong> Behavioral anomalies, insider threats.</p>
        </div>

        <div className="algorithm-card">
          <h4>3. Gaussian Mixture Model (GMM)</h4>
          <p><strong>How it works:</strong> Models data as mixture of Gaussian distributions. 
          Calculates probability of each point.</p>
          <p><strong>Why we use it:</strong> Provides probabilistic scores, soft clustering.</p>
          <p><strong>Best for:</strong> Statistical anomalies, rare events.</p>
        </div>
      </div>
    </div>
  )
}

function MetricsTab() {
  return (
    <div className="metrics-tab">
      <h3>📈 Model Performance Metrics</h3>
      <p>
        No metrics are shown here on purpose. Run <code>make reproduce</code> and read{' '}
        <code>results/report.md</code> (precision, recall, F1, PR-AUC, FPR, baselines and recall per
        attack type on AIT-LDSv2).
      </p>
    </div>
  )
}

function FeaturesTab() {
  const features = [
    {
      category: '⏰ Temporal Features (4)',
      items: [
        { name: 'hour_of_day', description: 'Hour when log occurred (0-23)', importance: 'high' },
        { name: 'day_of_week', description: 'Day of week (0=Monday)', importance: 'medium' },
        { name: 'is_weekend', description: 'Weekend activity flag', importance: 'medium' },
        { name: 'is_business_hours', description: 'Business hours (9 AM - 6 PM)', importance: 'high' }
      ]
    },
    {
      category: '📊 Frequency Features (4)',
      items: [
        { name: 'login_attempts_per_minute', description: 'Rate of login attempts', importance: 'critical' },
        { name: 'requests_per_second', description: 'HTTP request rate', importance: 'critical' },
        { name: 'unique_ips_last_hour', description: 'Distinct IPs seen', importance: 'medium' },
        { name: 'unique_endpoints_accessed', description: 'Number of endpoints accessed', importance: 'medium' }
      ]
    },
    {
      category: '📈 Rate Features (3)',
      items: [
        { name: 'failed_auth_rate', description: 'Proportion of failed authentications', importance: 'critical' },
        { name: 'error_rate_4xx', description: 'Client error rate', importance: 'medium' },
        { name: 'error_rate_5xx', description: 'Server error rate', importance: 'high' }
      ]
    },
    {
      category: '🧾 Event content (5)',
      items: [
        { name: 'status_class', description: 'HTTP status hundreds digit', importance: 'medium' },
        { name: 'is_known_ip', description: 'IP seen during training', importance: 'medium' },
        { name: 'path_length', description: 'Length of the request target', importance: 'medium' },
        { name: 'special_char_ratio', description: 'Share of unusual characters in the target', importance: 'medium' },
        { name: 'payload_entropy', description: 'Shannon entropy of the target', importance: 'medium' }
      ]
    },
    {
      category: '🎭 Behavioral Features (2)',
      items: [
        { name: 'bytes_transferred', description: 'Data volume (log scale)', importance: 'low' },
        { name: 'time_since_last_activity_sec', description: 'Time since last activity', importance: 'medium' }
      ]
    },
    {
      category: '🔐 Context Features (3)',
      items: [
        { name: 'is_privileged_user', description: 'root/admin user flag', importance: 'critical' },
        { name: 'is_sensitive_endpoint', description: 'Access to sensitive endpoints', importance: 'critical' },
        { name: 'is_known_user_agent', description: 'Recognized user agent', importance: 'medium' }
      ]
    }
  ]

  return (
    <div className="features-tab">
      <h3>🔧 Feature Engineering</h3>
      <p className="features-intro">
        The model uses <strong>21 engineered features</strong> extracted from raw security logs. 
        Features are deterministic, causal sliding-window statistics computed in-process (no Redis, database or GeoIP lookups).
      </p>

      <div className="features-list">
        {features.map((category, idx) => (
          <div key={idx} className="feature-category">
            <h4>{category.category}</h4>
            <div className="feature-items">
              {category.items.map((feature, fidx) => (
                <div key={fidx} className="feature-item">
                  <div className="feature-name">
                    <code>{feature.name}</code>
                    <span className={`importance-badge ${feature.importance}`}>
                      {feature.importance}
                    </span>
                  </div>
                  <p className="feature-desc">{feature.description}</p>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      <div className="feature-engineering-process">
        <h4>🔄 Feature Calculation Pipeline</h4>
        <div className="process-steps">
          <div className="process-step">
            <span className="step-num">1</span>
            <div>
              <h5>Parse Raw Log</h5>
              <p>Extract timestamp, IP, username, event type</p>
            </div>
          </div>
          <div className="process-step">
            <span className="step-num">2</span>
            <div>
              <h5>Sliding windows</h5>
              <p>Per-IP rates and ratios over the last 60 s / 5 min, in memory</p>
            </div>
          </div>
          <div className="process-step">
            <span className="step-num">3</span>
            <div>
              <h5>Request content</h5>
              <p>Length, special-character ratio and entropy of the request target</p>
            </div>
          </div>
          <div className="process-step">
            <span className="step-num">4</span>
            <div>
              <h5>Allow-list</h5>
              <p>Flag source IPs and user agents seen before</p>
            </div>
          </div>
          <div className="process-step">
            <span className="step-num">5</span>
            <div>
              <h5>Scale</h5>
              <p>Standardise with the training-set mean and variance</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ModelArchitecture
