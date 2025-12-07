import { useState } from 'react';
import axios from 'axios';
import { apiBaseURL } from '../utils/apiConfig';

export default function ApiSecurityAnalyzer() {
  const [endpointUrl, setEndpointUrl] = useState('');
  const [method, setMethod] = useState('GET');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

  const sampleEndpoints = [
    'http://api.example.com/users/1',
    'https://api.shop.com/api/v1/products',
    'https://admin.example.com/api/settings',
    'http://api.legacy.com/data'
  ];

  const handleAnalyze = async () => {
    if (!endpointUrl.trim()) {
      alert('Please enter an API endpoint URL');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${apiBaseURL}/api/security-analyze`, {
        endpoint_url: endpointUrl,
        method: method
      });
      setResult(response.data);
    } catch (error) {
      console.error('API security analysis error:', error);
      alert('Analysis failed: ' + error.message);
    }
    setLoading(false);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#facc15',
      low: '#22c55e'
    };
    return colors[severity] || '#39ff14';
  };

  const getRiskColor = (risk) => {
    return risk === 'CRITICAL' ? '#ef4444' : risk === 'HIGH' ? '#f97316' : risk === 'MEDIUM' ? '#facc15' : '#22c55e';
  };

  return (
    <div className="tool-container api-container">
      <h2 className="tool-title">🔗 API Security Analyzer</h2>
      <p className="tool-description">
        Analyze REST API endpoints for security vulnerabilities. Check authentication,
        headers, rate limiting, and OWASP API Security Top 10 compliance.
      </p>

      <div className="api-section">
        <h3>🌐 API Endpoint URL</h3>
        <input
          type="text"
          value={endpointUrl}
          onChange={(e) => setEndpointUrl(e.target.value)}
          placeholder="https://api.example.com/users/123"
          className="text-input"
        />
        <div className="sample-endpoints">
          <p>Try these:</p>
          {sampleEndpoints.map((url, idx) => (
            <button key={idx} onClick={() => setEndpointUrl(url)} className="btn-sample-endpoint">
              {url}
            </button>
          ))}
        </div>
      </div>

      <div className="api-section">
        <h3>📡 HTTP Method</h3>
        <div className="method-selector">
          {methods.map((m) => (
            <button
              key={m}
              className={`method-btn ${method === m ? 'active' : ''}`}
              onClick={() => setMethod(m)}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      <button
        onClick={handleAnalyze}
        disabled={loading || !endpointUrl.trim()}
        className="btn-primary"
      >
        {loading ? '⏳ Analyzing...' : '🔍 Analyze API Security'}
      </button>

      {result && (
        <div className="api-results">
          <div className="api-overview">
            <div className="score-section-api">
              <h3 className="api-score">{result.security_score}/100</h3>
              <p>Security Score</p>
            </div>
            <div className="risk-section-api">
              <h4>Risk Level</h4>
              <span className="risk-badge-api" style={{ backgroundColor: getRiskColor(result.risk_level) }}>
                {result.risk_level}
              </span>
            </div>
          </div>

          {result.vulnerabilities.length > 0 && (
            <div className="vulnerabilities-section">
              <h3>🚨 Vulnerabilities Found ({result.vulnerability_count})</h3>
              {result.vulnerabilities.map((vuln, idx) => (
                <div key={idx} className="vulnerability-card">
                  <div className="vuln-header">
                    <h4>{vuln.issue}</h4>
                    <span className="severity-badge-api" style={{ backgroundColor: getSeverityColor(vuln.severity) }}>
                      {vuln.severity.toUpperCase()}
                    </span>
                  </div>
                  <p className="vuln-owasp">{vuln.owasp}</p>
                  <p className="vuln-description">{vuln.description}</p>
                  <div className="vuln-remediation">
                    <strong>🔧 Remediation:</strong> {vuln.remediation}
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="security-headers-section">
            <h3>🛡️ Security Headers</h3>
            <div className="headers-grid">
              {Object.entries(result.security_headers).map(([header, value]) => (
                <div key={header} className={`header-card ${value === 'missing' ? 'missing' : 'present'}`}>
                  <h4>{header}</h4>
                  <p>{value}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="features-grid">
            <div className="feature-section">
              <h3>🔐 Authentication</h3>
              <div className="feature-content">
                {result.authentication.methods.map((auth, idx) => (
                  <span key={idx} className="auth-badge">{auth}</span>
                ))}
                <p className="feature-recommendation">{result.authentication.recommendation}</p>
              </div>
            </div>

            <div className="feature-section">
              <h3>⏱️ Rate Limiting</h3>
              <div className="feature-content">
                <p className={result.rate_limiting.enabled ? 'enabled' : 'disabled'}>
                  {result.rate_limiting.enabled ? '✅ Enabled' : '❌ Disabled'}
                </p>
                {result.rate_limiting.enabled && (
                  <p className="rate-limit">{result.rate_limiting.limit}</p>
                )}
              </div>
            </div>

            <div className="feature-section">
              <h3>🌍 CORS Policy</h3>
              <div className="feature-content">
                <p className={result.cors_policy.enabled ? 'enabled' : 'disabled'}>
                  {result.cors_policy.enabled ? '✅ Enabled' : '❌ Disabled'}
                </p>
                <p className="cors-origin">Origin: {result.cors_policy.allow_origin}</p>
                <p className="feature-recommendation">{result.cors_policy.recommendation}</p>
              </div>
            </div>
          </div>

          <div className="owasp-api-section">
            <h3>📋 OWASP API Security Top 10 (2023)</h3>
            <div className="owasp-api-list">
              {result.owasp_api_top_10.map((item, idx) => (
                <div key={idx} className="owasp-api-item">
                  {item}
                </div>
              ))}
            </div>
          </div>

          <div className="recommendations-section">
            <h3>🛡️ Security Recommendations</h3>
            <ul className="recommendations-list">
              {result.recommendations.map((rec, idx) => (
                <li key={idx}>{rec}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <div className="info-section api-info">
        <h4>📚 API Security Best Practices</h4>
        <ul>
          <li><strong>Authentication:</strong> Use OAuth 2.0, JWT tokens, API keys</li>
          <li><strong>Authorization:</strong> Implement RBAC, validate permissions per request</li>
          <li><strong>Rate Limiting:</strong> Prevent abuse and DDoS attacks</li>
          <li><strong>Input Validation:</strong> Sanitize and validate all inputs</li>
          <li><strong>HTTPS Only:</strong> Never transmit sensitive data over HTTP</li>
          <li><strong>Logging:</strong> Monitor API access and anomalies</li>
        </ul>
      </div>

      <div className="disclaimer api-disclaimer">
        ⚠️ <strong>Simulated Analysis</strong><br/>
        This tool provides educational guidance based on URL patterns. For production APIs,
        perform proper penetration testing and security audits.
      </div>
    </div>
  );
}
