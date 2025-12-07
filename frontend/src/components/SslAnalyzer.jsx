import React, { useState } from 'react';
import axios from 'axios';
import { API_URL } from '../utils/apiConfig';

export default function SslAnalyzer() {
  const [domain, setDomain] = useState('example.com');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleAnalyze = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_URL}/ssl/analyze`, { domain });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="tool-container">
      <div className="tool-header">
        <h2>🔐 SSL/TLS Certificate Analyzer</h2>
        <p>Analyze SSL/TLS certificates for security vulnerabilities (Simulated)</p>
      </div>

      <div className="tool-section">
        <label>Domain Name:</label>
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
        />

        <button onClick={handleAnalyze} disabled={loading} className="btn-primary">
          {loading ? 'Analyzing...' : 'Analyze Certificate'}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="result-section">
          <h3>SSL/TLS Certificate for {result.domain}</h3>

          <div className="ssl-status">
            <div className={`status-badge ${result.certificate.is_valid ? 'valid' : 'invalid'}`}>
              {result.certificate.is_valid ? '✓ Valid' : '✗ Invalid'}
            </div>
            <div className="security-rating">
              <span className="rating-label">Security Rating:</span>
              <span className="rating-value">{result.security_rating}</span>
            </div>
          </div>

          <div className="cert-details">
            <h4>Certificate Information</h4>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="label">Subject (CN):</span>
                <span className="value">{result.certificate.subject}</span>
              </div>
              <div className="detail-item">
                <span className="label">Issuer:</span>
                <span className="value">{result.certificate.issuer}</span>
              </div>
              <div className="detail-item">
                <span className="label">Serial:</span>
                <span className="value">{result.certificate.serial}</span>
              </div>
              <div className="detail-item">
                <span className="label">Signature Algorithm:</span>
                <span className="value">{result.certificate.signature_algorithm}</span>
              </div>
              <div className="detail-item">
                <span className="label">Key Bits:</span>
                <span className="value">{result.certificate.public_key_bits}</span>
              </div>
              <div className="detail-item">
                <span className="label">Validity:</span>
                <span className="value">{result.certificate.validity_days} days</span>
              </div>
              <div className="detail-item">
                <span className="label">Issued:</span>
                <span className="value">{result.certificate.issued}</span>
              </div>
              <div className="detail-item">
                <span className="label">Expires:</span>
                <span className="value">{result.certificate.expires}</span>
              </div>
            </div>
          </div>

          {result.certificate.san && result.certificate.san.length > 0 && (
            <div className="san-section">
              <h4>Subject Alternative Names (SANs)</h4>
              <div className="san-list">
                {result.certificate.san.map((name, idx) => (
                  <span key={idx} className="san-item">{name}</span>
                ))}
              </div>
            </div>
          )}

          <div className="tls-section">
            <h4>TLS Configuration</h4>
            <div className="tls-versions">
              <span className="label">Supported TLS Versions:</span>
              {result.tls_versions.map((ver, idx) => (
                <span key={idx} className="tls-badge">{ver}</span>
              ))}
            </div>
          </div>

          <p className="disclaimer">{result.disclaimer}</p>
        </div>
      )}
    </div>
  );
}
