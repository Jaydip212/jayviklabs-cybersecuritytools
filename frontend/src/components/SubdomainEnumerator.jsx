import React, { useState } from 'react';
import axios from 'axios';
import { API_URL } from '../utils/apiConfig';

export default function SubdomainEnumerator() {
  const [domain, setDomain] = useState('example.com');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleEnumerate = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_URL}/subdomain/enumerate`, { domain });
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
        <h2>🎯 Subdomain Enumerator</h2>
        <p>Discover subdomains using wordlist (Educational Simulation)</p>
      </div>

      <div className="tool-section">
        <label>Domain Name:</label>
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
        />

        <button onClick={handleEnumerate} disabled={loading} className="btn-primary">
          {loading ? 'Enumerating...' : 'Enumerate Subdomains'}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="result-section">
          <h3>Subdomain Enumeration Results</h3>

          <div className="enum-summary">
            <div className="summary-card">
              <span className="label">Domain</span>
              <span className="value">{result.domain}</span>
            </div>
            <div className="summary-card">
              <span className="label">Subdomains Found</span>
              <span className="value highlight">{result.subdomains_found}</span>
            </div>
          </div>

          {result.subdomains.length > 0 ? (
            <div className="subdomains-list">
              <h4>Discovered Subdomains:</h4>
              <table className="subdomains-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Subdomain</th>
                    <th>IP Address</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {result.subdomains.map((sub, idx) => (
                    <tr key={idx} className="subdomain-row">
                      <td className="idx">{idx + 1}</td>
                      <td className="subdomain">
                        <code>{sub.subdomain}</code>
                      </td>
                      <td className="ip">
                        <code>{sub.ip}</code>
                      </td>
                      <td className={`status ${sub.resolved ? 'resolved' : 'unresolved'}`}>
                        {sub.resolved ? '✓ Resolved' : '✗ Unresolved'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="no-results">No subdomains found</p>
          )}

          <p className="disclaimer">{result.disclaimer}</p>
        </div>
      )}
    </div>
  );
}
