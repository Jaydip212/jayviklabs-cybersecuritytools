import { useState } from 'react';
import axios from 'axios';
import { apiBaseURL } from '../utils/apiConfig';

export default function XssTester() {
  const [userInput, setUserInput] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const samplePayloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror="alert(1)">',
    '<svg onload="alert(\'XSS\')">',
    'javascript:alert(document.cookie)',
    '<iframe src="javascript:alert(\'XSS\')">',
    '<body onload="alert(1)">'
  ];

  const handleTest = async () => {
    if (!userInput.trim()) {
      alert('Please enter input to test');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${apiBaseURL}/security/xss-test`, {
        input: userInput,
        context: 'html'
      });
      setResult(response.data);
    } catch (error) {
      console.error('XSS test error:', error);
      alert('Test failed: ' + error.message);
    }
    setLoading(false);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#facc15',
      low: '#22c55e',
      none: '#39ff14'
    };
    return colors[severity] || '#39ff14';
  };

  return (
    <div className="tool-container xss-container">
      <h2 className="tool-title">⚡ XSS Vulnerability Tester</h2>
      <p className="tool-description">
        Test for Cross-Site Scripting (XSS) vulnerabilities. Detect malicious scripts,
        event handlers, and injection attempts. Learn XSS prevention techniques.
      </p>

      <div className="xss-section">
        <h3>💉 Input to Test</h3>
        <textarea
          value={userInput}
          onChange={(e) => setUserInput(e.target.value)}
          placeholder="Enter HTML/JavaScript to test for XSS vulnerabilities..."
          className="xss-textarea"
          rows={5}
        />
      </div>

      <div className="xss-section sample-payloads-section">
        <h3>🧪 Sample XSS Payloads</h3>
        <div className="payload-grid">
          {samplePayloads.map((payload, idx) => (
            <button
              key={idx}
              onClick={() => setUserInput(payload)}
              className="btn-sample-payload"
            >
              Payload {idx + 1}
            </button>
          ))}
        </div>
      </div>

      <button
        onClick={handleTest}
        disabled={loading || !userInput.trim()}
        className="btn-primary"
      >
        {loading ? '⏳ Testing...' : '🔍 Test for XSS'}
      </button>

      {result && (
        <div className="xss-results">
          <div className={`vulnerability-status ${result.is_vulnerable ? 'vulnerable' : 'safe'}`}>
            {result.is_vulnerable ? '⚠️ VULNERABLE' : '✅ SAFE'}
          </div>

          {result.is_vulnerable && (
            <>
              <div className="severity-indicator" style={{ borderColor: getSeverityColor(result.severity) }}>
                <h4>Severity: <span style={{ color: getSeverityColor(result.severity) }}>
                  {result.severity.toUpperCase()}
                </span></h4>
                <p>Found {result.attack_count} XSS attack pattern(s)</p>
              </div>

              <div className="attacks-detected-section">
                <h3>🚨 Attacks Detected</h3>
                {result.attacks_detected.map((attack, idx) => (
                  <div key={idx} className="attack-item-xss">
                    <div className="attack-header">
                      <span className="attack-type">{attack.type}</span>
                      <span className={`severity-badge-xss ${attack.severity}`}>
                        {attack.severity}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}

          <div className="output-comparison">
            <div className="output-box vulnerable-box">
              <h4>❌ Vulnerable Output</h4>
              <div className="code-display">{result.vulnerable_output}</div>
              <p className="output-note">Direct rendering - UNSAFE</p>
            </div>
            <div className="output-box safe-box">
              <h4>✅ Safe Output (Sanitized)</h4>
              <div className="code-display">{result.safe_output}</div>
              <p className="output-note">HTML encoded - SAFE</p>
            </div>
          </div>

          <div className="prevention-section">
            <h3>🛡️ XSS Prevention Tips</h3>
            <ul className="prevention-list">
              {result.prevention_tips.map((tip, idx) => (
                <li key={idx}>{tip}</li>
              ))}
            </ul>
          </div>

          <div className="xss-types-info">
            <h3>📚 XSS Types</h3>
            <div className="xss-types-grid">
              {Object.entries(result.xss_types).map(([type, desc]) => (
                <div key={type} className="xss-type-card">
                  <h4>{type.replace('_', ' ').toUpperCase()}</h4>
                  <p>{desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="info-section xss-info">
        <h4>📚 Understanding XSS</h4>
        <ul>
          <li><strong>Reflected XSS:</strong> User input immediately reflected in response</li>
          <li><strong>Stored XSS:</strong> Malicious script saved in database, executed for all users</li>
          <li><strong>DOM-based XSS:</strong> Vulnerability in client-side JavaScript code</li>
          <li><strong>Impact:</strong> Session hijacking, credential theft, malware distribution</li>
          <li><strong>Prevention:</strong> Input validation, output encoding, CSP headers</li>
        </ul>
      </div>

      <div className="disclaimer xss-disclaimer">
        ⚠️ <strong>Educational Only</strong><br/>
        This tool safely demonstrates XSS detection. All output is sanitized for your protection.
        Never test XSS on sites you don't own!
      </div>
    </div>
  );
}
