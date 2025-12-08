import React, { useState } from 'react'
import axios from 'axios'
import { API_URL } from '../utils/apiConfig'

export default function CsrfTokenGenerator(){
  const [token, setToken] = useState(null)
  const [loading, setLoading] = useState(false)

  const handleGenerateToken = async () => {
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/security/csrf-token`)
      setToken(response.data)
    } catch (error) {
      console.error('Error generating CSRF token:', error)
      alert('Failed to generate CSRF token')
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
    alert('Copied to clipboard!')
  }

  return (
    <section className="csrf-container card">
      <h2>🛡️ CSRF Token Generator</h2>
      
      <div className="csrf-section">
        <p>Generate secure CSRF protection tokens for state-changing operations</p>
        <button 
          className="btn-primary" 
          onClick={handleGenerateToken}
          disabled={loading}
        >
          {loading ? 'Generating...' : '🔐 Generate Token'}
        </button>
      </div>

      {token && (
        <div className="csrf-results">
          <div className="token-display">
            <h3>✅ CSRF Token Generated</h3>
            <div className="token-box">
              <code>{token.token}</code>
              <button 
                className="btn-copy" 
                onClick={() => copyToClipboard(token.token)}
              >
                📋 Copy
              </button>
            </div>
          </div>

          <div className="token-info">
            <div className="info-card">
              <strong>Expiration:</strong> {new Date(token.expiration * 1000).toLocaleString()}
            </div>
            <div className="info-card">
              <strong>Algorithm:</strong> {token.algorithm}
            </div>
            <div className="info-card">
              <strong>Strength:</strong> <span className="strength-badge">{token.strength}</span>
            </div>
          </div>

          <div className="validation-methods">
            <h3>Validation Methods</h3>
            <ul>
              {token.validation_methods.map((method, idx) => (
                <li key={idx}>✓ {method}</li>
              ))}
            </ul>
          </div>

          <div className="best-practices">
            <h3>Best Practices</h3>
            <ul>
              {token.best_practices.map((practice, idx) => (
                <li key={idx}>• {practice}</li>
              ))}
            </ul>
          </div>

          <div className="common-vulnerabilities">
            <h3>⚠️ Common Vulnerabilities to Avoid</h3>
            <ul>
              {token.common_vulnerabilities.map((vuln, idx) => (
                <li key={idx}>🔴 {vuln}</li>
              ))}
            </ul>
          </div>

          <div className="implementation-guide">
            <h3>Implementation Guide</h3>
            <div className="guide-box">
              <p><strong>Generation:</strong> {token.implementation_guide.generation.substring(0, 50)}...</p>
              <p><strong>Storage:</strong> {token.implementation_guide.storage}</p>
              <p><strong>Validation:</strong> {token.implementation_guide.validation}</p>
              <p><strong>Headers:</strong> {token.implementation_guide.headers}</p>
            </div>
          </div>

          <div className="csrf-disclaimer">
            <p>⚠️ <strong>Educational Disclaimer:</strong> This is a simulated CSRF token generator for learning purposes. In production, use well-tested frameworks and libraries for CSRF protection.</p>
          </div>
        </div>
      )}

      <div className="csrf-info">
        <h3>What is CSRF?</h3>
        <p>Cross-Site Request Forgery (CSRF) is an attack where an unauthorized command is transmitted from a user that the web application trusts. CSRF tokens help prevent these attacks by validating that requests originate from your application.</p>
      </div>
    </section>
  )
}
