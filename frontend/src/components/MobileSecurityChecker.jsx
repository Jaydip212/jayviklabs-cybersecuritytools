import { useState } from 'react';
import axios from 'axios';
import { apiBaseURL } from '../utils/apiConfig';

export default function MobileSecurityChecker() {
  const [appName, setAppName] = useState('');
  const [platform, setPlatform] = useState('android');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleCheck = async () => {
    if (!appName.trim()) {
      alert('Please enter an app name');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${apiBaseURL}/mobile/security-check`, {
        app_name: appName,
        platform: platform
      });
      setResult(response.data);
    } catch (error) {
      console.error('Mobile security check error:', error);
      alert('Check failed: ' + error.message);
    }
    setLoading(false);
  };

  const getStatusIcon = (status) => {
    return status === 'pass' ? '✅' : status === 'warning' ? '⚠️' : '❌';
  };

  const getStatusColor = (status) => {
    return status === 'pass' ? '#22c55e' : status === 'warning' ? '#facc15' : '#ef4444';
  };

  const getRiskColor = (risk) => {
    return risk === 'LOW' ? '#22c55e' : risk === 'MEDIUM' ? '#facc15' : '#ef4444';
  };

  return (
    <div className="tool-container mobile-container">
      <h2 className="tool-title">📱 Mobile Security Checker</h2>
      <p className="tool-description">
        Analyze mobile app security posture. Check for common vulnerabilities and best practices
        compliance. Covers Android and iOS security requirements.
      </p>

      <div className="mobile-section">
        <h3>📱 App Information</h3>
        <input
          type="text"
          value={appName}
          onChange={(e) => setAppName(e.target.value)}
          placeholder="Enter app name (e.g., MyBankingApp)"
          className="text-input"
        />
      </div>

      <div className="mobile-section">
        <h3>🔧 Platform</h3>
        <div className="platform-selector">
          <button
            className={`platform-btn ${platform === 'android' ? 'active' : ''}`}
            onClick={() => setPlatform('android')}
          >
            🤖 Android
          </button>
          <button
            className={`platform-btn ${platform === 'ios' ? 'active' : ''}`}
            onClick={() => setPlatform('ios')}
          >
            🍎 iOS
          </button>
        </div>
      </div>

      <button
        onClick={handleCheck}
        disabled={loading || !appName.trim()}
        className="btn-primary"
      >
        {loading ? '⏳ Analyzing...' : '🔍 Analyze Security'}
      </button>

      {result && (
        <div className="mobile-results">
          <div className="security-score-section">
            <div className="score-gauge">
              <div
                className="score-fill"
                style={{
                  width: `${result.security_score}%`,
                  backgroundColor: result.security_score >= 80 ? '#22c55e' : result.security_score >= 60 ? '#facc15' : '#ef4444'
                }}
              />
            </div>
            <div className="score-info">
              <h3 className="score-value">{result.security_score}/100</h3>
              <p className="score-label">Security Score</p>
            </div>
          </div>

          <div className="risk-level-section">
            <h4>Risk Level:</h4>
            <span className="risk-badge-mobile" style={{ backgroundColor: getRiskColor(result.risk_level) }}>
              {result.risk_level}
            </span>
          </div>

          <div className="checks-summary">
            <div className="summary-stat">
              <span className="stat-value passed">{result.checks_passed}</span>
              <span className="stat-label">Passed</span>
            </div>
            <div className="summary-stat">
              <span className="stat-value warnings">{result.checks_warning}</span>
              <span className="stat-label">Warnings</span>
            </div>
            <div className="summary-stat">
              <span className="stat-value failed">{result.checks_failed}</span>
              <span className="stat-label">Failed</span>
            </div>
          </div>

          <div className="security-checks-section">
            <h3>🔒 Security Checks</h3>
            {result.security_checks.map((check, idx) => (
              <div key={idx} className="check-card">
                <div className="check-header">
                  <span className="check-icon">{getStatusIcon(check.status)}</span>
                  <div className="check-info">
                    <h4>{check.category}</h4>
                    <p className="check-description">{check.check}</p>
                  </div>
                  <span className={`severity-badge-mobile ${check.severity}`}>
                    {check.severity}
                  </span>
                </div>
                {check.status !== 'pass' && (
                  <div className="check-recommendation">
                    <strong>💡 Recommendation:</strong> {check.recommendation}
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="owasp-section">
            <h3>📋 OWASP Mobile Top 10</h3>
            <div className="owasp-grid">
              {result.owasp_mobile_top_10.map((item, idx) => (
                <div key={idx} className="owasp-item">
                  {item}
                </div>
              ))}
            </div>
          </div>

          <div className="recommendations-section">
            <h3>🛡️ General Recommendations</h3>
            <ul className="recommendations-list">
              {result.recommendations.map((rec, idx) => (
                <li key={idx}>{rec}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <div className="info-section mobile-info">
        <h4>📚 Mobile App Security</h4>
        <ul>
          <li><strong>Data Storage:</strong> Encrypt sensitive data, use Keychain/Keystore</li>
          <li><strong>Network:</strong> Certificate pinning, TLS 1.2+, avoid HTTP</li>
          <li><strong>Authentication:</strong> Biometrics, MFA, secure session management</li>
          <li><strong>Code Protection:</strong> Obfuscation, anti-tampering, root/jailbreak detection</li>
          <li><strong>Permissions:</strong> Request minimum necessary permissions</li>
        </ul>
      </div>

      <div className="disclaimer mobile-disclaimer">
        ⚠️ <strong>Simulated Analysis</strong><br/>
        This tool provides educational guidance. For production apps, perform proper security audits
        and penetration testing following OWASP MSTG guidelines.
      </div>
    </div>
  );
}
