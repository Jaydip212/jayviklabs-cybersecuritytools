import React, {useState} from 'react'
import axios from 'axios'
import { API_URL } from '../utils/apiConfig'

export default function HashDemo(){
  const [text, setText] = useState('jayvik-labs-demo')
  const [hashes, setHashes] = useState(null)
  const [loading, setLoading] = useState(false)

  const generateHashes = async () => {
    if (!text.trim()) return
    
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/hashes`, {
        text: text
      })
      setHashes(response.data)
    } catch (error) {
      console.error('Hash generation failed:', error)
      setHashes({
        error: 'Hash generation failed. Make sure the backend is running.'
      })
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = (value) => {
    navigator.clipboard.writeText(value)
  }

  const getHashSecurity = (hashType) => {
    const security = {
      'md5': { level: 'BROKEN', color: '#dc3545' },
      'sha1': { level: 'DEPRECATED', color: '#fd7e14' },
      'sha256': { level: 'SECURE', color: '#28a745' }
    }
    return security[hashType.toLowerCase()] || { level: 'UNKNOWN', color: '#6c757d' }
  }

  return (
    <section className="card">
      <h3>🔗 Cryptographic Hash Demonstrator</h3>
      <p className="card-description">
        Compare different hash algorithms and learn about their security implications
      </p>

      <div className="input-group">
        <input 
          type="text"
          value={text} 
          onChange={(e) => setText(e.target.value)}
          placeholder="Enter text to hash..."
          className="text-input"
        />
        <button 
          onClick={generateHashes}
          disabled={loading || !text.trim()}
          className="hash-btn"
        >
          {loading ? 'Hashing...' : 'Generate Hashes'}
        </button>
      </div>

      {hashes && !hashes.error && (
        <div className="result-panel">
          <div className="original-text">
            <strong>Original:</strong> {hashes.original}
          </div>

          <div className="hash-results">
            {['md5', 'sha1', 'sha256'].map((hashType) => {
              const security = getHashSecurity(hashType)
              return (
                <div key={hashType} className="hash-item">
                  <div className="hash-header">
                    <span className="hash-name">{hashType.toUpperCase()}</span>
                    <span 
                      className="security-badge"
                      style={{ backgroundColor: security.color }}
                    >
                      {security.level}
                    </span>
                  </div>
                  
                  <div className="hash-value-container">
                    <code className="hash-value">{hashes[hashType]}</code>
                    <button 
                      className="copy-btn"
                      onClick={() => copyToClipboard(hashes[hashType])}
                      title="Copy to clipboard"
                    >
                      📋
                    </button>
                  </div>
                  
                  <div className="hash-note">
                    {hashes.educational_notes[hashType]}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {hashes && hashes.error && (
        <div className="error-panel">
          <p>{hashes.error}</p>
        </div>
      )}

      <div className="info-box">
        <h4>Hash Function Properties:</h4>
        <ul>
          <li><strong>Deterministic:</strong> Same input always produces same output</li>
          <li><strong>One-way:</strong> Cannot reverse hash to get original input</li>
          <li><strong>Avalanche effect:</strong> Small input change = big output change</li>
          <li><strong>Collision resistant:</strong> Hard to find two inputs with same hash</li>
        </ul>
        
        <h4>Security Timeline:</h4>
        <ul>
          <li><strong>MD5 (1991):</strong> Broken since 2004, do not use!</li>
          <li><strong>SHA-1 (1995):</strong> Deprecated since 2017, avoid</li>
          <li><strong>SHA-256 (2001):</strong> Currently secure, recommended</li>
        </ul>
      </div>
    </section>
  )
}