const API_BASE = '/api/v1'

export interface HealthResponse {
  status: string
  version: string
  timestamp: string
  uptime_seconds: number
}

export interface StatsResponse {
  logs_analyzed_24h: number
  anomalies_detected_24h: number
  anomaly_rate: number
  model_version: string
  last_retrain: string
  models: Record<string, any>
}

export interface Anomaly {
  log_id: string
  is_anomaly: boolean
  risk_score: number
  risk_level: string
  confidence: string
  features: Record<string, any>
  reasons: string[]
  recommended_action: string
  similar_anomalies: number
  model_scores: {
    isolation_forest: number
    dbscan: number
    gmm: number
  }
  processing_time_ms: number
  timestamp: string
}

export interface AnomaliesResponse {
  total: number
  page: number
  page_size: number
  anomalies: Anomaly[]
}

async function fetchAPI<T>(endpoint: string): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`)
  
  if (!response.ok) {
    throw new Error(`API Error: ${response.statusText}`)
  }
  
  return response.json()
}

export const getHealth = (): Promise<HealthResponse> => 
  fetchAPI('/health')

export const getStats = (): Promise<StatsResponse> => 
  fetchAPI('/stats')

export const getAnomalies = (params?: {
  limit?: number
  offset?: number
  hours?: number
  min_risk_score?: number
}): Promise<AnomaliesResponse> => {
  const query = new URLSearchParams()
  
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        query.append(key, value.toString())
      }
    })
  }
  
  return fetchAPI(`/anomalies?${query}`)
}

export const analyzeLog = async (
  logLine: string,
  source: string,
  metadata?: Record<string, any>
): Promise<Anomaly> => {
  const response = await fetch(`${API_BASE}/logs/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      log_line: logLine,
      source,
      metadata,
    }),
  })
  
  if (!response.ok) {
    throw new Error(`Analysis failed: ${response.statusText}`)
  }
  
  return response.json()
}
