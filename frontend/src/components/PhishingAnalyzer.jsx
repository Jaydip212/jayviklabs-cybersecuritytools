import React, {useState} from 'react'
import axios from 'axios'
import { API_URL } from '../utils/apiConfig'

const riskColor = (level) => {
  switch (level) {
    case 'High':
      return '#f97316'
    case 'Moderate':
      return '#facc15'
    case 'Low':
      return '#10b981'
    default:
      return '#2dd4bf'
  }
}

export default function PhishingAnalyzer(){
  const [emailText, setEmailText] = useState('Hello user, your account will be suspended in 12 hours. Click http://192.168.1.50/login to verify your password immediately.')
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading] = useState(false)

  const analyzeEmail = async () => {
    if (!emailText.trim()) return
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/phishing/analyze`, { text: emailText })
      setAnalysis(response.data)
    } catch (error) {
      console.error('Phishing analysis failed:', error)
      setAnalysis({
        error: 'Analysis failed. Ensure the backend is running and reachable.'
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="card">
      <h3>📧 Phishing Email Analyzer</h3>
      <p className="card-description">
        Paste suspicious messages to review common phishing indicators (educational simulation only).
      </p>

      <div className="input-group column">
        <textarea
          value={emailText}
          onChange={(e) => setEmailText(e.target.value)}
          className="text-area"
          rows={6}
          placeholder="Paste email content here..."
        />
        <button
          onClick={analyzeEmail}
          disabled={loading || !emailText.trim()}
          className="analyze-btn"
        >
          {loading ? 'Analyzing...' : 'Analyze Message'}
        </button>
      </div>

      {analysis && !analysis.error && (
        <div className="result-panel">
          <div className="phish-summary">
            <div className="risk-meter" style={{ borderColor: riskColor(analysis.risk_level) }}>
              <span className="risk-score" style={{ color: riskColor(analysis.risk_level) }}>
                {analysis.risk_score}
              </span>
              <span className="risk-label">Risk Score</span>
              <span className="risk-level">{analysis.risk_level}</span>
            </div>
            <div className="summary-text">
              <p>{analysis.summary}</p>
            </div>
          </div>

          {analysis.indicators.length > 0 && (
            <div className="indicator-list">
              <h4>Flagged Indicators:</h4>
              <ul>
                {analysis.indicators.map((indicator, index) => (
                  <li key={index} className={`indicator severity-${indicator.severity}`}>
                    <strong>{indicator.type}:</strong> {indicator.detail}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="tips">
            <h4>Stay Safe:</h4>
            <ul>
              {analysis.tips.map((tip, index) => (
                <li key={index}>{tip}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {analysis && analysis.error && (
        <div className="error-panel">
          <p>{analysis.error}</p>
        </div>
      )}

      <div className="info-box">
        <h4>Ethical Reminder:</h4>
        <ul>
          <li>Use this tool to recognize phishing patterns — never engage attackers.</li>
          <li>Report suspicious emails through official organizational processes.</li>
          <li>Verify requests for credentials using trusted contact information.</li>
        </ul>
      </div>
    </section>
  )
}
