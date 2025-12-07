import React, { useState } from 'react';
import axios from 'axios';
import { API_URL } from '../utils/apiConfig';

export default function SqlInjectionLab() {
  const [userInput, setUserInput] = useState('');
  const [queryType, setQueryType] = useState('login');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleTest = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_URL}/security/sql-injection-test`, {
        input: userInput,
        query_type: queryType
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const samplePayloads = {
    login: "' OR '1'='1",
    advanced: "'; DROP TABLE users; --",
    union: "' UNION SELECT * FROM admin_users --"
  };

  return (
    <div className="tool-container">
      <div className="tool-header">
        <h2>🛡️ SQL Injection Lab</h2>
        <p>Learn how SQL injection works and how to prevent it (Educational)</p>
      </div>

      <div className="tool-section">
        <label>Query Type:</label>
        <select value={queryType} onChange={(e) => setQueryType(e.target.value)}>
          <option value="login">Login Form</option>
          <option value="search">Search Query</option>
        </select>

        <label>User Input:</label>
        <input
          type="text"
          value={userInput}
          onChange={(e) => setUserInput(e.target.value)}
          placeholder="Enter test input..."
        />

        <div className="sample-payloads">
          <button
            onClick={() => setUserInput(samplePayloads.login)}
            className="btn-payload"
          >
            Classic Injection
          </button>
          <button
            onClick={() => setUserInput(samplePayloads.advanced)}
            className="btn-payload"
          >
            DROP Table
          </button>
          <button
            onClick={() => setUserInput(samplePayloads.union)}
            className="btn-payload"
          >
            UNION Injection
          </button>
        </div>

        <button onClick={handleTest} disabled={loading} className="btn-primary">
          {loading ? 'Testing...' : 'Test for SQL Injection'}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="result-section">
          <h3>SQL Injection Analysis</h3>

          <div className={`vulnerability-badge ${result.is_vulnerable ? 'vulnerable' : 'safe'}`}>
            {result.is_vulnerable ? '🚨 VULNERABLE' : '✓ SAFE'}
          </div>

          {result.is_vulnerable && result.attacks_detected.length > 0 && (
            <div className="attacks-detected">
              <h4>Detected Attack Patterns:</h4>
              <div className="attack-list">
                {result.attacks_detected.map((attack, idx) => (
                  <div key={idx} className="attack-item">
                    <span className="attack-name">{attack}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="query-comparison">
            <div className="query-box vulnerable">
              <h4>❌ Vulnerable Code:</h4>
              <code className="query-code">{result.vulnerable_query}</code>
              <p className="vulnerability-note">Direct string concatenation allows injection</p>
            </div>

            <div className="query-box safe">
              <h4>✅ Secure Code:</h4>
              <code className="query-code">{result.safe_query}</code>
              <p className="security-note">Parameterized query prevents injection</p>
            </div>
          </div>

          <div className="prevention-tips">
            <h4>🛡️ Prevention Methods:</h4>
            <ul className="tips-list">
              {result.prevention_tips.map((tip, idx) => (
                <li key={idx}>{tip}</li>
              ))}
            </ul>
          </div>

          <div className="severity-info">
            <span className="label">Severity Level:</span>
            <span className={`severity-badge ${result.severity.toLowerCase()}`}>
              {result.severity}
            </span>
          </div>

          <p className="disclaimer">{result.disclaimer}</p>
        </div>
      )}

      <div className="educational-info">
        <h4>📚 Why SQL Injection Matters:</h4>
        <p>
          SQL Injection is one of the most critical web application vulnerabilities. It allows attackers to:
        </p>
        <ul className="info-list">
          <li>Bypass authentication mechanisms</li>
          <li>Extract sensitive data from databases</li>
          <li>Modify or delete database records</li>
          <li>Execute administrative operations</li>
          <li>Potentially compromise the entire system</li>
        </ul>
      </div>
    </div>
  );
}
