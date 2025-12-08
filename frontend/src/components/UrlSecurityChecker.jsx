import React, { useState } from 'react'
import axios from 'axios'
import { API_URL } from '../utils/apiConfig'

export default function UrlSecurityChecker(){
  const [url, setUrl] = useState('')
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)

  const sampleUrls = [
    'https://example-banking-com.verifyaccount.xyz/update?token=12345&password=change',
    'http://192.168.1.1/admin?cmd=ls;rm%20-rf%20/',
    'https://secure-api.example.com/users?id=123',
    'https://paypal-verify.ru/login?email=user@email.com'
  ]

  const handleCheck = async () => {
    if (!url.trim()) {
      alert('Please enter a URL to check')
      return
    }
    
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/security/check-url`, {
        url: url
      })
      setResults(response.data)
    } catch (error) {
      console.error('Error checking URL:', error)
      alert('Failed to check URL')
    } finally {
      setLoading(false)
    }
  }

  const loadSampleUrl = (sampleUrl) => {
    setUrl(sampleUrl)
    setResults(null)
  }

  const getRiskColor = (riskLevel) => {
    const colors = {
      'CRITICAL': '#ef4444',
      'HIGH': '#f97316',
      'MEDIUM': '#facc15',
      'LOW': '#22c55e'
    }
    return colors[riskLevel] || '#fff'
  }

  return (
    <section className="url-checker-container card">
      <h2>🔗 URL Security Checker</h2>
      
      <div className="url-section">
        <p>Analyze URLs for phishing, malware, and security risks</p>
        
        <div className="url-input-area">
          <input 
            type="text"
            className="url-input"
            placeholder="Enter URL to check... (e.g., https://example.com/page?param=value)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleCheck()}
          />
        </div>

        <div className="sample-urls">
          <p>Try sample URLs:</p>
          {sampleUrls.map((sampleUrl, idx) => (
            <button 
              key={idx} 
              className="btn-sample-url"
              onClick={() => loadSampleUrl(sampleUrl)}
            >
              Sample {idx + 1}
            </button>
          ))}
        </div>

        <button 
          className="btn-primary" 
          onClick={handleCheck}
          disabled={loading}
        >
          {loading ? 'Checking...' : '🔍 Check URL'}
        </button>
      </div>

      {results && (
        <div className="url-results">
          <div className="url-overview">
            <h3>URL Analysis Results</h3>
            <div className="url-info-grid">
              <div className="url-info-card">
                <span className="label">Original URL</span>
                <code className="url-display">{results.original_url}</code>
              </div>
              <div className="url-info-card">
                <span className="label">Shortened URL</span>
                <code className="url-display">{results.shortened_url}</code>
              </div>
              <div className="url-info-card">
                <span className="label">Scheme</span>
                <span className="value">{results.scheme}</span>
              </div>
              <div className="url-info-card">
                <span className="label">Domain</span>
                <span className="value">{results.domain}</span>
              </div>
            </div>
          </div>

          <div className="security-assessment">
            <h3>🛡️ Security Assessment</h3>
            <div className="assessment-grid">
              <div className="assessment-box">
                <span className="assessment-label">Security Score</span>
                <div className="score-bar">
                  <div 
                    className="score-fill"
                    style={{
                      width: `${results.security_score}%`,
                      backgroundColor: getRiskColor(results.risk_level)
                    }}
                  />
                </div>
                <span className="score-value">{results.security_score}%</span>
              </div>
              <div className="assessment-box">
                <span className="assessment-label">Risk Level</span>
                <span 
                  className="risk-badge"
                  style={{
                    backgroundColor: getRiskColor(results.risk_level),
                    color: 'white'
                  }}
                >
                  {results.risk_level}
                </span>
              </div>
              <div className="assessment-box">
                <span className="assessment-label">Safe to Share</span>
                <span className={`safety-badge ${results.safe_to_share ? 'safe' : 'unsafe'}`}>
                  {results.safe_to_share ? '✅ YES' : '❌ NO'}
                </span>
              </div>
              <div className="assessment-box">
                <span className="assessment-label">Issues Found</span>
                <span className="issue-count">{results.issues_count}</span>
              </div>
            </div>
          </div>

          {results.issues.length > 0 && (
            <div className="issues-section">
              <h3>⚠️ Issues Detected</h3>
              <div className="issues-list">
                {results.issues.map((issue, idx) => (
                  <div key={idx} className="url-issue-card">
                    <div className="issue-header">
                      <span className="issue-type">{issue.type}</span>
                      <span 
                        className="severity-badge"
                        style={{backgroundColor: getRiskColor(issue.severity.toUpperCase())}}
                      >
                        {issue.severity.toUpperCase()}
                      </span>
                    </div>
                    <p className="issue-description">{issue.description}</p>
                    <p className="issue-impact">💡 Impact: {issue.impact}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="recommendations-section">
            <h3>✅ Security Recommendations</h3>
            <ul className="recommendations-list">
              {results.recommendations.map((rec, idx) => (
                <li key={idx}>• {rec}</li>
              ))}
            </ul>
          </div>

          <div className="url-disclaimer">
            <p>⚠️ <strong>Educational Disclaimer:</strong> This is a simulated URL checker for learning purposes. Always verify URLs independently and use professional security tools for critical decisions.</p>
          </div>
        </div>
      )}

      <div className="url-info">
        <h3>What is URL Security?</h3>
        <p>URLs can be weaponized for phishing, malware distribution, and social engineering attacks. This tool helps identify common security issues in URLs such as suspicious domains, encoding, and parameter values.</p>
      </div>
    </section>
  )
}
