import React, {useState} from 'react'
import axios from 'axios'
import { API_URL } from '../utils/apiConfig'

export default function CryptoLab(){
  const [activeTab, setActiveTab] = useState('aes')
  const [text, setText] = useState('Hello Jayvik Labs!')
  const [caesarShift, setCaesarShift] = useState(3)
  const [aesResult, setAesResult] = useState(null)
  const [caesarResult, setCaesarResult] = useState(null)
  const [base64Result, setBase64Result] = useState(null)
  const [loading, setLoading] = useState(false)

  const encryptAES = async () => {
    if (!text.trim()) return
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/encrypt/aes`, { text })
      setAesResult(response.data)
    } catch (error) {
      console.error('AES encryption failed:', error)
    } finally {
      setLoading(false)
    }
  }

  const decryptAES = async () => {
    if (!aesResult) return
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/decrypt/aes`, aesResult)
      alert(`Decrypted: ${response.data.plaintext}`)
    } catch (error) {
      alert('Decryption failed!')
    } finally {
      setLoading(false)
    }
  }

  const encryptCaesar = async () => {
    if (!text.trim()) return
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/encrypt/caesar`, {
        text,
        shift: caesarShift
      })
      setCaesarResult(response.data)
    } catch (error) {
      console.error('Caesar encryption failed:', error)
    } finally {
      setLoading(false)
    }
  }

  const processBase64 = async () => {
    if (!text.trim()) return
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/base64`, { text })
      setBase64Result(response.data)
    } catch (error) {
      console.error('Base64 operation failed:', error)
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = (value) => {
    navigator.clipboard.writeText(value)
  }

  return (
    <section className="card">
      <h3>🔐 Encryption & Encoding Lab</h3>
      <p className="card-description">
        Explore different encryption methods and encoding techniques
      </p>

      <div className="input-group">
        <input 
          type="text"
          value={text} 
          onChange={(e) => setText(e.target.value)}
          placeholder="Enter text to encrypt/encode..."
          className="text-input"
        />
      </div>

      <div className="tab-container">
        <div className="tab-buttons">
          <button 
            className={activeTab === 'aes' ? 'tab-btn active' : 'tab-btn'}
            onClick={() => setActiveTab('aes')}
          >
            AES Encryption
          </button>
          <button 
            className={activeTab === 'caesar' ? 'tab-btn active' : 'tab-btn'}
            onClick={() => setActiveTab('caesar')}
          >
            Caesar Cipher
          </button>
          <button 
            className={activeTab === 'base64' ? 'tab-btn active' : 'tab-btn'}
            onClick={() => setActiveTab('base64')}
          >
            Base64 Encoding
          </button>
        </div>

        <div className="tab-content">
          {activeTab === 'aes' && (
            <div className="aes-tab">
              <div className="crypto-info">
                <h4>🔒 AES (Advanced Encryption Standard)</h4>
                <p>Symmetric encryption - same key for encrypt/decrypt</p>
              </div>
              
              <button 
                onClick={encryptAES}
                disabled={loading || !text.trim()}
                className="crypto-btn"
              >
                {loading ? 'Encrypting...' : 'Encrypt with AES'}
              </button>

              {aesResult && (
                <div className="result-panel">
                  <div className="crypto-result">
                    <label>Ciphertext:</label>
                    <div className="value-container">
                      <code>{aesResult.ciphertext}</code>
                      <button onClick={() => copyToClipboard(aesResult.ciphertext)}>📋</button>
                    </div>
                  </div>
                  
                  <div className="crypto-result">
                    <label>IV (Initialization Vector):</label>
                    <div className="value-container">
                      <code>{aesResult.iv}</code>
                      <button onClick={() => copyToClipboard(aesResult.iv)}>📋</button>
                    </div>
                  </div>

                  <button 
                    onClick={decryptAES}
                    disabled={loading}
                    className="crypto-btn secondary"
                  >
                    {loading ? 'Decrypting...' : 'Decrypt (Server)'}
                  </button>
                </div>
              )}
            </div>
          )}

          {activeTab === 'caesar' && (
            <div className="caesar-tab">
              <div className="crypto-info">
                <h4>📜 Caesar Cipher</h4>
                <p>Classical substitution cipher - shifts letters by a fixed amount</p>
              </div>
              
              <div className="caesar-controls">
                <label>Shift Amount:</label>
                <input 
                  type="number"
                  value={caesarShift}
                  onChange={(e) => setCaesarShift(parseInt(e.target.value) || 0)}
                  min="1"
                  max="25"
                  className="shift-input"
                />
              </div>

              <button 
                onClick={encryptCaesar}
                disabled={loading || !text.trim()}
                className="crypto-btn"
              >
                {loading ? 'Encrypting...' : 'Apply Caesar Cipher'}
              </button>

              {caesarResult && (
                <div className="result-panel">
                  <div className="crypto-result">
                    <label>Result:</label>
                    <div className="value-container">
                      <code>{caesarResult.ciphertext}</code>
                      <button onClick={() => copyToClipboard(caesarResult.ciphertext)}>📋</button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'base64' && (
            <div className="base64-tab">
              <div className="crypto-info">
                <h4>📦 Base64 Encoding</h4>
                <p>Encoding method (NOT encryption!) - easily reversible</p>
              </div>
              
              <button 
                onClick={processBase64}
                disabled={loading || !text.trim()}
                className="crypto-btn"
              >
                {loading ? 'Processing...' : 'Encode to Base64'}
              </button>

              {base64Result && !base64Result.error && (
                <div className="result-panel">
                  <div className="crypto-result">
                    <label>Original:</label>
                    <div className="value-container">
                      <code>{base64Result.original}</code>
                    </div>
                  </div>
                  
                  <div className="crypto-result">
                    <label>Encoded:</label>
                    <div className="value-container">
                      <code>{base64Result.encoded}</code>
                      <button onClick={() => copyToClipboard(base64Result.encoded)}>📋</button>
                    </div>
                  </div>
                  
                  <div className="crypto-result">
                    <label>Decoded:</label>
                    <div className="value-container">
                      <code>{base64Result.decoded}</code>
                    </div>
                  </div>
                  
                  <div className="warning-note">
                    ⚠️ {base64Result.note}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="info-box">
        <h4>Cryptography Fundamentals:</h4>
        <ul>
          <li><strong>Symmetric:</strong> Same key for encryption and decryption (AES)</li>
          <li><strong>Asymmetric:</strong> Different keys (public/private key pairs)</li>
          <li><strong>Classical:</strong> Historical methods like Caesar cipher</li>
          <li><strong>Encoding:</strong> Data representation (Base64) - NOT security!</li>
        </ul>
      </div>
    </section>
  )
}