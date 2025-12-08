import React, { useState } from 'react'
import axios from 'axios'
import { API_URL } from '../utils/apiConfig'

export default function LogAnalyzer(){
  const [logContent, setLogContent] = useState('')
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)

  const sampleLogs = [
    `2025-12-08 10:23:45 - User login attempt from 192.168.1.100
2025-12-08 10:24:12 - SQL error: SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin
2025-12-08 10:25:00 - API Key exposed: sk_live_abcdef123456789
2025-12-08 10:26:33 - XSS attempt detected: <script>alert('xss')</script>`,
    `2025-12-08 10:30:00 - [ERROR] Database connection failed
2025-12-08 10:31:15 - Path traversal attempt: ../../../../etc/passwd
2025-12-08 10:32:45 - Command injection: ls; rm -rf /
2025-12-08 10:33:20 - 403 Forbidden - Unauthorized access attempt`
  ]

  const handleAnalyze = async () => {
    if (!logContent.trim()) {
      alert('Please enter log content to analyze')
      return
    }
    
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/security/analyze-logs`, {
        log_content: logContent
      })
      setResults(response.data)
    } catch (error) {
      console.error('Error analyzing logs:', error)
      alert('Failed to analyze logs')
    } finally {
      setLoading(false)
    }
  }

  const loadSampleLog = (index) => {
    setLogContent(sampleLogs[index])
    setResults(null)
  }

  const getSeverityColor = (severity) => {
    const colors = {
      'critical': '#ef4444',
      'high': '#f97316',
      'medium': '#facc15',
      'low': '#22c55e'
    }
    return colors[severity] || '#fff'
  }

  return (
    <section className="log-analyzer-container card">
      <h2>📊 Log Security Analyzer</h2>
      
      <div className="log-section">
        <p>Analyze logs for security threats, vulnerabilities, and suspicious patterns</p>
        
        <div className="log-input-area">
          <textarea 
            className="log-textarea"
            placeholder="Paste your log content here... (server logs, access logs, error logs, etc.)"
            value={logContent}
            onChange={(e) => setLogContent(e.target.value)}
            rows="6"
          />
        </div>

        <div className="sample-logs">
          <p>Try sample logs:</p>
          {sampleLogs.map((_, idx) => (
            <button 
              key={idx} 
              className="btn-sample-log"
              onClick={() => loadSampleLog(idx)}
            >
              Sample {idx + 1}
            </button>
          ))}
        </div>

        <button 
          className="btn-primary" 
          onClick={handleAnalyze}
          disabled={loading}
        >
          {loading ? 'Analyzing...' : '🔍 Analyze Logs'}
        </button>
      </div>

      {results && (
        <div className="log-results">
          <div className="log-overview">
            <h3>Analysis Results</h3>
            <div className="stats-grid">
              <div className="stat-box">
                <span className="stat-label">Total Lines</span>
                <span className="stat-value">{results.total_lines}</span>
              </div>
              <div className="stat-box">
                <span className="stat-label">Issues Found</span>
                <span className="stat-value" style={{color: results.issues_found > 0 ? '#ef4444' : '#22c55e'}}>
                  {results.issues_found}
                </span>
              </div>
              <div className="stat-box">
                <span className="stat-label">Security Score</span>
                <span className="stat-value">{results.security_score}%</span>
              </div>
              <div className="stat-box">
                <span className="stat-label">Risk Level</span>
                <span className="stat-value" style={{color: getSeverityColor(results.risk_level.toLowerCase())}}>
                  {results.risk_level}
                </span>
              </div>
            </div>
          </div>

          {results.issues.length > 0 && (
            <div className="issues-section">
              <h3>🔴 Issues Detected</h3>
              <div className="issues-list">
                {results.issues.map((issue, idx) => (
                  <div key={idx} className="issue-card">
                    <div className="issue-header">
                      <span className="issue-type">{issue.threat_type}</span>
                      <span 
                        className="severity-badge" 
                        style={{background: getSeverityColor(issue.severity), color: 'white'}}
                      >
                        {issue.severity.toUpperCase()}
                      </span>
                    </div>
                    <div className="issue-content">
                      <code>{issue.content}</code>
                    </div>
                    <div className="issue-line">Line {issue.line}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="recommendations-section">
            <h3>✅ Recommendations</h3>
            <ul className="recommendations-list">
              {results.recommendations.map((rec, idx) => (
                <li key={idx}>• {rec}</li>
              ))}
            </ul>
          </div>

          <div className="patterns-checked">
            <h3>Patterns Checked</h3>
            <div className="patterns-grid">
              {results.patterns_checked.map((pattern, idx) => (
                <div key={idx} className="pattern-badge">
                  {pattern.replace(/_/g, ' ').toUpperCase()}
                </div>
              ))}
            </div>
          </div>

          <div className="log-disclaimer">
            <p>⚠️ <strong>Educational Disclaimer:</strong> This analysis is simulated for learning purposes. For production systems, use professional SIEM tools and log management solutions.</p>
          </div>
        </div>
      )}

      <div className="log-info">
        <h3>What is Log Analysis?</h3>
        <p>Log analysis helps identify security incidents, anomalies, and vulnerabilities by examining system and application logs. This tool demonstrates common threat patterns found in logs.</p>
      </div>
    </section>
  )
}
