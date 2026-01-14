import { useState, useEffect } from 'react'
import './ModelArchitecture.css'

interface ModelMetrics {
  f1_score: number
  precision: number
  recall: number
  accuracy: number
  roc_auc: number
  confusion_matrix: {
    tn: number
    fp: number
    fn: number
    tp: number
  }
  fpr: number
  fnr: number
}

interface ModelStats {
  model_version: string
  training_time_sec: number
  test_metrics: ModelMetrics
  validation_metrics: ModelMetrics
  baseline: {
    f1_score: number
    accuracy: number
  }
  improvement: {
    f1_score: number
    accuracy: number
  }
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
      // En producción, esto vendría del API
      // GET /api/v1/model/stats
      const response = await fetch('/api/v1/stats')
      const data = await response.json()
      
      // Por ahora usamos datos hardcodeados basados en el training
      setModelStats({
        model_version: data.model_version || 'v1.0.0',
        training_time_sec: 3.5,
        test_metrics: {
          f1_score: 0.966,
          precision: 0.935,
          recall: 1.000,
          accuracy: 0.997,
          roc_auc: 1.000,
          confusion_matrix: {
            tn: 1993,
            fp: 7,
            fn: 0,
            tp: 100
          },
          fpr: 0.0035,
          fnr: 0.0
        },
        validation_metrics: {
          f1_score: 0.971,
          precision: 0.943,
          recall: 1.000,
          accuracy: 0.997,
          roc_auc: 1.000,
          confusion_matrix: {
            tn: 1994,
            fp: 6,
            fn: 0,
            tp: 100
          },
          fpr: 0.003,
          fnr: 0.0
        },
        baseline: {
          f1_score: 0.0,
          accuracy: 0.952
        },
        improvement: {
          f1_score: 0.966,
          accuracy: 0.044
        }
      })
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
          <span className="trained-badge">Trained & Production Ready</span>
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
        {activeTab === 'overview' && <OverviewTab stats={modelStats} />}
        {activeTab === 'architecture' && <ArchitectureTab />}
        {activeTab === 'metrics' && <MetricsTab stats={modelStats} />}
        {activeTab === 'features' && <FeaturesTab />}
      </div>
    </section>
  )
}

function OverviewTab({ stats }: { stats: ModelStats | null }) {
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
          <h3>⚡ Performance</h3>
          <div className="metrics-mini">
            <div className="metric-mini">
              <span className="metric-label">F1-Score</span>
              <span className="metric-value success">{((stats?.test_metrics.f1_score || 0) * 100).toFixed(1)}%</span>
            </div>
            <div className="metric-mini">
              <span className="metric-label">Recall</span>
              <span className="metric-value success">{((stats?.test_metrics.recall || 0) * 100).toFixed(1)}%</span>
            </div>
            <div className="metric-mini">
              <span className="metric-label">FPR</span>
              <span className="metric-value warning">{((stats?.test_metrics.fpr || 0) * 100).toFixed(2)}%</span>
            </div>
          </div>
        </div>

        <div className="overview-card">
          <h3>🚀 Training</h3>
          <div className="training-info">
            <p><strong>Time:</strong> {stats?.training_time_sec.toFixed(1)}s</p>
            <p><strong>Samples:</strong> 10,500 (95% normal, 5% anomalies)</p>
            <p><strong>Features:</strong> 21 engineered features</p>
          </div>
        </div>

        <div className="overview-card">
          <h3>📊 vs Baseline</h3>
          <div className="comparison">
            <div className="comparison-item">
              <span>Baseline (Dummy):</span>
              <span className="bad">F1 = 0.0%</span>
            </div>
            <div className="comparison-item">
              <span>Our Ensemble:</span>
              <span className="good">F1 = 96.6%</span>
            </div>
            <div className="improvement">
              <span className="improvement-badge">+96.6 points improvement</span>
            </div>
          </div>
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
            <p>Calculate 21 Features</p>
            <div className="feature-categories">
              <span className="feature-cat">⏰ Temporal (4)</span>
              <span className="feature-cat">📊 Frequency (4)</span>
              <span className="feature-cat">📈 Rates (3)</span>
              <span className="feature-cat">🌍 Geographic (3)</span>
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
                <p className="weight">Weight: 50%</p>
                <p className="description">Fast outlier detection via tree isolation</p>
                <div className="model-params">
                  <span>n_estimators: 100</span>
                  <span>contamination: 0.05</span>
                </div>
              </div>

              <div className="model-card dbscan">
                <h5>DBSCAN</h5>
                <p className="weight">Weight: 30%</p>
                <p className="description">Density-based clustering anomaly detection</p>
                <div className="model-params">
                  <span>eps: 5.0</span>
                  <span>min_samples: 50</span>
                </div>
              </div>

              <div className="model-card gmm">
                <h5>Gaussian Mixture</h5>
                <p className="weight">Weight: 20%</p>
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

function MetricsTab({ stats }: { stats: ModelStats | null }) {
  if (!stats) return <div>Loading metrics...</div>

  const { test_metrics, validation_metrics } = stats

  return (
    <div className="metrics-tab">
      <h3>📈 Model Performance Metrics</h3>

      <div className="metrics-comparison">
        <div className="metrics-set">
          <h4>Validation Set (20%)</h4>
          <div className="metrics-grid">
            <MetricCard 
              label="F1-Score" 
              value={validation_metrics.f1_score} 
              format="percent"
              description="Harmonic mean of precision and recall"
            />
            <MetricCard 
              label="Precision" 
              value={validation_metrics.precision} 
              format="percent"
              description="% of detected anomalies that are correct"
            />
            <MetricCard 
              label="Recall" 
              value={validation_metrics.recall} 
              format="percent"
              description="% of actual anomalies detected"
            />
            <MetricCard 
              label="Accuracy" 
              value={validation_metrics.accuracy} 
              format="percent"
              description="Overall classification accuracy"
            />
            <MetricCard 
              label="ROC-AUC" 
              value={validation_metrics.roc_auc} 
              format="percent"
              description="Area under ROC curve"
            />
            <MetricCard 
              label="FPR" 
              value={validation_metrics.fpr} 
              format="percent"
              description="False Positive Rate (lower is better)"
              warning
            />
          </div>
        </div>

        <div className="metrics-set">
          <h4>Test Set (20%) - Final Evaluation</h4>
          <div className="metrics-grid">
            <MetricCard 
              label="F1-Score" 
              value={test_metrics.f1_score} 
              format="percent"
              description="Harmonic mean of precision and recall"
            />
            <MetricCard 
              label="Precision" 
              value={test_metrics.precision} 
              format="percent"
              description="% of detected anomalies that are correct"
            />
            <MetricCard 
              label="Recall" 
              value={test_metrics.recall} 
              format="percent"
              description="% of actual anomalies detected"
            />
            <MetricCard 
              label="Accuracy" 
              value={test_metrics.accuracy} 
              format="percent"
              description="Overall classification accuracy"
            />
            <MetricCard 
              label="ROC-AUC" 
              value={test_metrics.roc_auc} 
              format="percent"
              description="Area under ROC curve"
            />
            <MetricCard 
              label="FPR" 
              value={test_metrics.fpr} 
              format="percent"
              description="False Positive Rate (lower is better)"
              warning
            />
          </div>
        </div>
      </div>

      <div className="confusion-matrix-section">
        <h4>🎯 Confusion Matrix (Test Set)</h4>
        <div className="confusion-matrix">
          <div className="matrix-grid">
            <div className="matrix-label">Predicted →</div>
            <div className="matrix-label">Normal</div>
            <div className="matrix-label">Anomaly</div>
            
            <div className="matrix-label vertical">
              <span>Actual</span>
              <span>↓</span>
            </div>
            
            <div className="matrix-cell tn">
              <div className="cell-label">True Negative</div>
              <div className="cell-value">{test_metrics.confusion_matrix.tn}</div>
              <div className="cell-desc">Correct normal</div>
            </div>
            
            <div className="matrix-cell fp">
              <div className="cell-label">False Positive</div>
              <div className="cell-value">{test_metrics.confusion_matrix.fp}</div>
              <div className="cell-desc">False alarms</div>
            </div>
            
            <div className="matrix-label">Normal</div>
            <div className="matrix-label">Anomaly</div>
            
            <div className="matrix-cell fn">
              <div className="cell-label">False Negative</div>
              <div className="cell-value">{test_metrics.confusion_matrix.fn}</div>
              <div className="cell-desc">Missed threats</div>
            </div>
            
            <div className="matrix-cell tp">
              <div className="cell-label">True Positive</div>
              <div className="cell-value">{test_metrics.confusion_matrix.tp}</div>
              <div className="cell-desc">Correct anomalies</div>
            </div>
          </div>
        </div>

        <div className="matrix-insights">
          <div className="insight success">
            <strong>✅ Perfect Recall:</strong> Detected all {test_metrics.confusion_matrix.tp} anomalies (0 false negatives)
          </div>
          <div className="insight warning">
            <strong>⚠️ Low FPR:</strong> Only {test_metrics.confusion_matrix.fp} false positives out of {test_metrics.confusion_matrix.tn + test_metrics.confusion_matrix.fp} normal logs ({(test_metrics.fpr * 100).toFixed(2)}%)
          </div>
        </div>
      </div>

      <div className="training-details">
        <h4>📊 Training Details</h4>
        <div className="training-grid">
          <div className="training-item">
            <span className="training-label">Data Split:</span>
            <span className="training-value">60% Train / 20% Val / 20% Test</span>
          </div>
          <div className="training-item">
            <span className="training-label">Training Time:</span>
            <span className="training-value">{stats.training_time_sec.toFixed(1)}s</span>
          </div>
          <div className="training-item">
            <span className="training-label">Data Leakage:</span>
            <span className="training-value success">✅ None Detected</span>
          </div>
          <div className="training-item">
            <span className="training-label">Stratification:</span>
            <span className="training-value">✅ Class-balanced splits</span>
          </div>
        </div>
      </div>
    </div>
  )
}

interface MetricCardProps {
  label: string
  value: number
  format: 'percent' | 'raw'
  description: string
  warning?: boolean
}

function MetricCard({ label, value, format, description, warning }: MetricCardProps) {
  const displayValue = format === 'percent' ? `${(value * 100).toFixed(1)}%` : value.toFixed(3)
  const colorClass = warning 
    ? (value < 0.01 ? 'success' : value < 0.05 ? 'warning' : 'danger')
    : (value >= 0.95 ? 'success' : value >= 0.80 ? 'warning' : 'danger')

  return (
    <div className="metric-card">
      <div className="metric-header">
        <span className="metric-label">{label}</span>
        <span className={`metric-value ${colorClass}`}>{displayValue}</span>
      </div>
      <p className="metric-description">{description}</p>
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
      category: '🌍 Geographic Features (3)',
      items: [
        { name: 'geographic_distance_km', description: 'Distance from typical location', importance: 'high' },
        { name: 'is_known_country', description: 'Request from known country', importance: 'medium' },
        { name: 'is_known_ip', description: 'IP in whitelist', importance: 'high' }
      ]
    },
    {
      category: '🎭 Behavioral Features (4)',
      items: [
        { name: 'bytes_transferred', description: 'Data volume (log scale)', importance: 'low' },
        { name: 'time_since_last_activity_sec', description: 'Time since last activity', importance: 'medium' },
        { name: 'session_duration_sec', description: 'Session length', importance: 'low' },
        { name: 'payload_entropy', description: 'Randomness of payload', importance: 'high' }
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
        Features are calculated in real-time using Redis (rates), PostgreSQL (historical), and GeoIP (location).
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
              <h5>Query Redis</h5>
              <p>Get rates (login attempts, requests/sec) from last 60s</p>
            </div>
          </div>
          <div className="process-step">
            <span className="step-num">3</span>
            <div>
              <h5>Query PostgreSQL</h5>
              <p>Get historical data (last activity, unique IPs)</p>
            </div>
          </div>
          <div className="process-step">
            <span className="step-num">4</span>
            <div>
              <h5>GeoIP Lookup</h5>
              <p>Calculate geographic distance, country check</p>
            </div>
          </div>
          <div className="process-step">
            <span className="step-num">5</span>
            <div>
              <h5>Normalize & Scale</h5>
              <p>Convert to [0, 1] range for ML model</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ModelArchitecture
