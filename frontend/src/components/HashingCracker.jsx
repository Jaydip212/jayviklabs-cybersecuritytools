import { useState } from 'react';
import axios from 'axios';
import { apiBaseURL } from '../utils/apiConfig';

export default function HashingCracker() {
  const [hashValue, setHashValue] = useState('');
  const [hashType, setHashType] = useState('md5');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [crackerProgress, setCrackerProgress] = useState(0);

  const handleCrack = async () => {
    if (!hashValue.trim()) {
      setMessage('⚠️ Please enter a hash to crack');
      return;
    }

    setLoading(true);
    setMessage('🔄 Cracking hash...');
    setCrackerProgress(0);

    try {
      const response = await axios.post(`${apiBaseURL}/hashes/crack`, {
        hash: hashValue,
        hash_type: hashType,
      });

      setResult(response.data);

      if (response.data.found) {
        setMessage(`✅ Password found: "${response.data.password}"`);
        setCrackerProgress(100);
      } else {
        setMessage(`⚠️ ${response.data.message}`);
        setCrackerProgress(100);
      }
    } catch (error) {
      setMessage(`❌ Error: ${error.message}`);
    }

    setLoading(false);
  };

  // Common test hashes for demo
  const testHashes = {
    'password': {
      md5: '5f4dcc3b5aa765d61d8327deb882cf99',
      sha1: '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8',
      sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
    },
    'admin': {
      md5: '21232f297a57a5a743894a0e4a801fc3',
      sha1: 'd033e22ae348aeb5660fc2140aec35850c4da997',
      sha256: '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'
    },
    'letmein': {
      md5: '0d107d09f5bbe40cade3de5c71e9e9b7',
      sha1: '6c146b6d24f10d89427c18793586953acaee4615',
      sha256: '8d969eef6ecad3c29a3a873fba6ee2e737410c34b96d4debf5cac0b19fbc9faa'
    }
  };

  const loadTestHash = (password) => {
    setHashValue(testHashes[password][hashType]);
    setResult(null);
    setMessage('');
    setCrackerProgress(0);
  };

  return (
    <div className="tool-container cracker-container">
      <h2 className="tool-title">📊 Hashing Cracker</h2>
      <p className="tool-description">
        Attempt to crack hashes using a rainbow table of common passwords.
        Learn how weak passwords are compromised. This is a simulated tool
        with a limited wordlist for educational purposes.
      </p>

      {/* Hash Type Selector */}
      <div className="cracker-section">
        <h3>🔐 Hash Type</h3>
        <div className="hash-type-selector">
          {['md5', 'sha1', 'sha256'].map((type) => (
            <button
              key={type}
              className={`hash-type-btn ${hashType === type ? 'active' : ''}`}
              onClick={() => {
                setHashType(type);
                setResult(null);
                setMessage('');
                setCrackerProgress(0);
              }}
            >
              {type.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Hash Input */}
      <div className="cracker-section">
        <h3>🔤 Hash Value</h3>
        <textarea
          value={hashValue}
          onChange={(e) => setHashValue(e.target.value.toLowerCase())}
          placeholder="Paste the hash you want to crack (md5, sha1, or sha256)..."
          className="hash-input"
          spellCheck="false"
        />
      </div>

      {/* Test Hashes */}
      <div className="cracker-section test-hashes">
        <h3>🧪 Try These Test Hashes:</h3>
        <div className="test-hash-buttons">
          {Object.keys(testHashes).map((password) => (
            <div key={password} className="test-hash-item">
              <p className="test-password">Password: <strong>{password}</strong></p>
              <button
                className="btn-test-hash"
                onClick={() => loadTestHash(password)}
              >
                Load {hashType.toUpperCase()} Hash
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Crack Button */}
      <button
        onClick={handleCrack}
        disabled={loading || !hashValue.trim()}
        className="btn-primary"
      >
        {loading ? '⏳ Cracking...' : '🔨 Crack Hash'}
      </button>

      {/* Progress Bar */}
      {loading && (
        <div className="progress-section">
          <div className="progress-bar">
            <div 
              className="progress-fill" 
              style={{ width: `${Math.min(crackerProgress, 100)}%` }}
            />
          </div>
          <p className="progress-text">Attempting to crack...</p>
        </div>
      )}

      {/* Message */}
      {message && <div className="message-box">{message}</div>}

      {/* Results */}
      {result && (
        <div className={`cracker-results ${result.found ? 'found' : 'not-found'}`}>
          <div className="result-grid">
            <div className="result-item">
              <h4>🎯 Status</h4>
              <p className={`result-value ${result.found ? 'success' : 'failure'}`}>
                {result.found ? '✅ FOUND' : '❌ NOT FOUND'}
              </p>
            </div>
            <div className="result-item">
              <h4>🔀 Attempts</h4>
              <p className="result-value">{result.attempts}</p>
            </div>
            <div className="result-item">
              <h4>⏱️ Time Estimate</h4>
              <p className="result-value">{result.time_estimate}</p>
            </div>
            {result.found && (
              <div className="result-item">
                <h4>🔓 Password</h4>
                <p className="result-value password-result">{result.password}</p>
              </div>
            )}
          </div>

          {result.found && (
            <button
              onClick={() => {
                navigator.clipboard.writeText(result.password);
                setMessage('✅ Password copied to clipboard!');
              }}
              className="btn-secondary"
            >
              📋 Copy Password
            </button>
          )}

          {!result.found && result.tip && (
            <div className="tip-box">
              <strong>💡 Tip:</strong> {result.tip}
            </div>
          )}
        </div>
      )}

      {/* Educational Info */}
      <div className="info-section cracker-info">
        <h4>📚 Understanding Hash Cracking</h4>
        <ul>
          <li><strong>Rainbow Tables:</strong> Pre-computed hash→password mappings for fast lookup</li>
          <li><strong>Brute Force:</strong> Tries every possible combination (slower)</li>
          <li><strong>Dictionary Attack:</strong> Uses wordlists of common passwords (faster)</li>
          <li><strong>Salt:</strong> Random data added to hashes prevents rainbow table attacks</li>
          <li><strong>Strong Passwords:</strong> Long + complex + unique are hard to crack</li>
          <li><strong>Hash Strength:</strong> Slower algorithms (bcrypt, scrypt) make cracking harder</li>
        </ul>
      </div>

      {/* Security Warning */}
      <div className="disclaimer cracker-disclaimer">
        ⚠️ <strong>Educational Only</strong><br/>
        Real password cracking requires more computing power. Actual hackers use GPU clusters and larger wordlists.
        Protect your passwords by using strong, unique ones and enabling multi-factor authentication!
      </div>
    </div>
  );
}
