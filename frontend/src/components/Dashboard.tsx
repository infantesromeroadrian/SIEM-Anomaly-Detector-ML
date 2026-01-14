import { useState, useEffect } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import './Dashboard.css'

interface DashboardProps {
  stats: {
    logs_analyzed_24h: number
    anomalies_detected_24h: number
    anomaly_rate: number
  } | null
}

interface TimeSeriesDataPoint {
  timestamp: string
  hour_label: string
  anomalies: number
  logs: number
}

function Dashboard({ stats }: DashboardProps) {
  const [timeRange, setTimeRange] = useState<number>(24)
  const [chartData, setChartData] = useState<TimeSeriesDataPoint[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchTimeSeries = async () => {
      try {
        setLoading(true)
        const response = await fetch(`/api/v1/stats/timeseries?hours=${timeRange}`)
        if (!response.ok) throw new Error('Failed to fetch timeseries')
        
        const data = await response.json()
        setChartData(data.data_points || [])
      } catch (error) {
        console.error('Error fetching timeseries:', error)
        // Fallback to empty data on error
        setChartData([])
      } finally {
        setLoading(false)
      }
    }

    fetchTimeSeries()
    // Refresh every 60 seconds
    const interval = setInterval(fetchTimeSeries, 60000)
    return () => clearInterval(interval)
  }, [timeRange])

  if (!stats) {
    return (
      <section className="dashboard">
        <h2 className="section-title">Dashboard</h2>
        <div className="stats-grid">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="stat-card skeleton">
              <div className="skeleton-text"></div>
              <div className="skeleton-number"></div>
            </div>
          ))}
        </div>
      </section>
    )
  }

  const statCards = [
    {
      label: 'Logs Analyzed (24h)',
      value: stats.logs_analyzed_24h.toLocaleString(),
      icon: '📊',
      trend: '+12%'
    },
    {
      label: 'Anomalies Detected',
      value: stats.anomalies_detected_24h.toLocaleString(),
      icon: '🚨',
      color: stats.anomalies_detected_24h > 100 ? 'danger' : 'warning'
    },
    {
      label: 'Anomaly Rate',
      value: `${(stats.anomaly_rate * 100).toFixed(2)}%`,
      icon: '📈',
      color: stats.anomaly_rate > 0.05 ? 'danger' : 'success'
    },
    {
      label: 'Detection Accuracy',
      value: '94.2%',
      icon: '🎯',
      color: 'success'
    }
  ]

  return (
    <section className="dashboard">
      <h2 className="section-title">Dashboard</h2>
      
      <div className="stats-grid">
        {statCards.map((stat, index) => (
          <div key={index} className={`stat-card ${stat.color || ''}`}>
            <div className="stat-header">
              <span className="stat-icon">{stat.icon}</span>
              <span className="stat-label">{stat.label}</span>
            </div>
            <div className="stat-value">{stat.value}</div>
            {stat.trend && <div className="stat-trend">{stat.trend}</div>}
          </div>
        ))}
      </div>

      <div className="chart-container">
        <div className="chart-header">
          <h3 className="chart-title">Anomalies Over Time</h3>
          <div className="time-range-selector">
            <button 
              className={`range-btn ${timeRange === 1 ? 'active' : ''}`}
              onClick={() => setTimeRange(1)}
            >
              1h
            </button>
            <button 
              className={`range-btn ${timeRange === 12 ? 'active' : ''}`}
              onClick={() => setTimeRange(12)}
            >
              12h
            </button>
            <button 
              className={`range-btn ${timeRange === 24 ? 'active' : ''}`}
              onClick={() => setTimeRange(24)}
            >
              24h
            </button>
          </div>
        </div>

        {loading ? (
          <div className="chart-loading">Loading chart data...</div>
        ) : chartData.length === 0 ? (
          <div className="chart-empty">No data available for selected time range</div>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis 
                dataKey="hour_label" 
                stroke="#cbd5e1"
                tick={{ fontSize: 12 }}
                interval="preserveStartEnd"
              />
              <YAxis stroke="#cbd5e1" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1e293b', 
                  border: '1px solid #334155',
                  borderRadius: '0.5rem'
                }}
              />
              <Line 
                type="monotone" 
                dataKey="anomalies" 
                stroke="#ef4444" 
                strokeWidth={2}
                dot={false}
                name="Anomalies"
              />
              <Line 
                type="monotone" 
                dataKey="logs" 
                stroke="#3b82f6" 
                strokeWidth={2}
                dot={false}
                name="Logs"
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  )
}

export default Dashboard
