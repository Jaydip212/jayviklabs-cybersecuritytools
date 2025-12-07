import React, {useState} from 'react'
import axios from 'axios'
import { API_URL } from '../utils/apiConfig'

export default function PasswordAnalyzer(){
  const [password, setPassword] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const analyzePassword = async () => {
    if (!password.trim()) return
    
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/password-strength`, {
        password: password
      })
      setResult(response.data)
    } catch (error) {
      console.error('Password analysis failed:', error)
      setResult({
        error: 'Analysis failed. Make sure the backend is running.'
      })
    } finally {
      setLoading(false)
    }
  }

  const getStrengthColor = (strength) => {
    const colors = {
      'Very Weak': '#dc3545',
      'Weak': '#fd7e14',
      'Fair': '#ffc107',
      'Good': '#20c997',
      'Strong': '#28a745'
    }
    return colors[strength] || '#6c757d'
  }

  return (
    <section className="card">
      <h3>🔐 Password Strength Analyzer</h3>
      <p className="card-description">
        Test password strength and learn security best practices
      </p>
      
      <div className="input-group">
        <input 
          type="password"
          value={password} 
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter a password to analyze..."
          className="password-input"
        />
        <button 
          onClick={analyzePassword}
          disabled={loading || !password.trim()}
          className="analyze-btn"
        >
          {loading ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>

      {result && !result.error && (
        <div className="result-panel">
          <div className="strength-indicator">
            <span 
              className="strength-badge"
              style={{ backgroundColor: getStrengthColor(result.strength) }}
            >
              {result.strength}
            </span>
            <span className="score">Score: {result.score}/4</span>
          </div>
          
          <div className="analysis-details">
            <div className="length-info">Length: {result.length} characters</div>
            
            {result.reasons.length > 0 && (
              <div className="improvement-section">
                <h4>Areas for Improvement:</h4>
                <ul>
                  {result.reasons.map((reason, index) => (
                    <li key={index}>{reason}</li>
                  ))}
                </ul>
              </div>
            )}
            
            {result.suggestions.length > 0 && (
              <div className="suggestions-section">
                <h4>Security Tips:</h4>
                <ul>
                  {result.suggestions.map((suggestion, index) => (
                    <li key={index}>{suggestion}</li>
                  ))}
                </ul>
              </div>
            )}
            
            <div className="educational-note">
              💡 {result.educational_note}
            </div>
          </div>
        </div>
      )}

      {result && result.error && (
        <div className="error-panel">
          <p>{result.error}</p>
        </div>
      )}

      <div className="info-box">
        <h4>Password Security Tips:</h4>
        <ul>
          <li>Use at least 12 characters</li>
          <li>Mix uppercase, lowercase, numbers, and symbols</li>
          <li>Avoid common words and patterns</li>
          <li>Use unique passwords for each account</li>
          <li>Consider using a password manager</li>
        </ul>
      </div>
    </section>
  )
}