import React, { useState } from 'react';
import axios from 'axios';
import { API_URL } from '../utils/apiConfig';

export default function WhoisLookup() {
  const [domain, setDomain] = useState('example.com');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleLookup = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_URL}/whois/lookup`, { domain });
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
        <h2>📋 WHOIS Lookup</h2>
        <p>Look up domain registration details (Simulated)</p>
      </div>

      <div className="tool-section">
        <label>Domain Name:</label>
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
        />

        <button onClick={handleLookup} disabled={loading} className="btn-primary">
          {loading ? 'Looking up...' : 'Lookup WHOIS'}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="result-section">
          <h3>WHOIS Information for {result.domain}</h3>

          <div className="whois-grid">
            <div className="whois-section">
              <h4>📊 Registration Details</h4>
              <div className="detail-item">
                <span className="label">Domain:</span>
                <span className="value">{result.domain}</span>
              </div>
              <div className="detail-item">
                <span className="label">Registrar:</span>
                <span className="value">{result.registrar}</span>
              </div>
              <div className="detail-item">
                <span className="label">Status:</span>
                <span className={`status-badge ${result.status === 'ok' ? 'active' : 'inactive'}`}>
                  {result.status}
                </span>
              </div>
              <div className="detail-item">
                <span className="label">DNSSEC:</span>
                <span className="value">{result.dnssec}</span>
              </div>
            </div>

            <div className="whois-section">
              <h4>📅 Dates</h4>
              <div className="detail-item">
                <span className="label">Created:</span>
                <span className="value">{result.created_date}</span>
              </div>
              <div className="detail-item">
                <span className="label">Updated:</span>
                <span className="value">{result.updated_date}</span>
              </div>
              <div className="detail-item">
                <span className="label">Expires:</span>
                <span className="value">{result.expiry_date}</span>
              </div>
            </div>

            <div className="whois-section">
              <h4>👤 Registrant Info</h4>
              <div className="detail-item">
                <span className="label">Name:</span>
                <span className="value">{result.registrant.name}</span>
              </div>
              <div className="detail-item">
                <span className="label">Email:</span>
                <span className="value">{result.registrant.email}</span>
              </div>
              <div className="detail-item">
                <span className="label">Country:</span>
                <span className="value">{result.registrant.country}</span>
              </div>
            </div>

            <div className="whois-section">
              <h4>🌐 Nameservers</h4>
              <div className="ns-list">
                {result.name_servers.map((ns, idx) => (
                  <div key={idx} className="ns-item">
                    <code>{ns}</code>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <p className="disclaimer">{result.disclaimer}</p>
        </div>
      )}
    </div>
  );
}
