import React, { useState } from 'react';
import axios from 'axios';
import { API_URL } from '../utils/apiConfig';

export default function PasswordGenerator() {
  const [length, setLength] = useState(16);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeUppercase, setIncludeUppercase] = useState(true);
  const [includeLowercase, setIncludeLowercase] = useState(true);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    setCopied(false);
    try {
      const response = await axios.post(`${API_URL}/password/generate`, {
        length,
        include_symbols: includeSymbols,
        include_numbers: includeNumbers,
        include_uppercase: includeUppercase,
        include_lowercase: includeLowercase
      });
      setResult(response.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(result.password);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="tool-container">
      <div className="tool-header">
        <h2>🔐 Strong Password Generator</h2>
        <p>Create cryptographically strong passwords with custom rules</p>
      </div>

      <div className="tool-section">
        <label>Password Length:</label>
        <div className="length-slider">
          <input
            type="range"
            min="8"
            max="128"
            value={length}
            onChange={(e) => setLength(parseInt(e.target.value))}
            className="slider"
          />
          <span className="length-display">{length} characters</span>
        </div>

        <div className="checkbox-group">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={includeLowercase}
              onChange={(e) => setIncludeLowercase(e.target.checked)}
            />
            <span>Lowercase (a-z)</span>
          </label>

          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={includeUppercase}
              onChange={(e) => setIncludeUppercase(e.target.checked)}
            />
            <span>Uppercase (A-Z)</span>
          </label>

          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={includeNumbers}
              onChange={(e) => setIncludeNumbers(e.target.checked)}
            />
            <span>Numbers (0-9)</span>
          </label>

          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={includeSymbols}
              onChange={(e) => setIncludeSymbols(e.target.checked)}
            />
            <span>Symbols (!@#$%^&*)</span>
          </label>
        </div>

        <button onClick={handleGenerate} disabled={loading} className="btn-primary">
          {loading ? 'Generating...' : 'Generate Password'}
        </button>
      </div>

      {result && (
        <div className="result-section">
          <h3>Generated Password</h3>

          <div className="password-display">
            <code className="password-box">{result.password}</code>
            <button onClick={handleCopy} className="btn-copy">
              {copied ? '✓ Copied!' : '📋 Copy'}
            </button>
          </div>

          <div className="password-info-grid">
            <div className="info-card">
              <span className="label">Strength:</span>
              <span className={`strength-badge ${result.strength.toLowerCase()}`}>
                {result.strength}
              </span>
            </div>
            <div className="info-card">
              <span className="label">Entropy:</span>
              <span className="value">{result.entropy_bits.toFixed(1)} bits</span>
            </div>
            <div className="info-card">
              <span className="label">Length:</span>
              <span className="value">{result.length} chars</span>
            </div>
          </div>

          <div className="tips-section">
            <h4>💡 Password Best Practices:</h4>
            <ul className="tips-list">
              {result.tips.map((tip, idx) => (
                <li key={idx}>{tip}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
