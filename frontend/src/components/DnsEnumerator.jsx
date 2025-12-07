import React, { useState } from 'react';
import axios from 'axios';
import { API_URL } from '../utils/apiConfig';

export default function DnsEnumerator() {
  const [domain, setDomain] = useState('example.com');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('A');

  const handleEnumerate = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_URL}/dns/enumerate`, { domain });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const recordTabs = ['A', 'AAAA', 'MX', 'TXT', 'NS'];

  return (
    <div className="tool-container">
      <div className="tool-header">
        <h2>🌐 DNS Enumeration</h2>
        <p>Enumerate DNS records for a domain (Educational Simulation)</p>
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
          {loading ? 'Enumerating...' : 'Enumerate DNS'}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="result-section">
          <h3>DNS Records for {result.domain}</h3>

          <div className="dns-tabs">
            {recordTabs.map((tab) => (
              <button
                key={tab}
                className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab}
              </button>
            ))}
          </div>

          <div className="dns-records">
            {activeTab === 'A' && result.records.A && (
              <div className="record-type">
                <h4>A Records (IPv4 Addresses)</h4>
                {result.records.A.map((rec, idx) => (
                  <div key={idx} className="record-item">
                    <code>{rec.value}</code>
                    <span className="ttl">TTL: {rec.ttl}</span>
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'AAAA' && result.records.AAAA && (
              <div className="record-type">
                <h4>AAAA Records (IPv6 Addresses)</h4>
                {result.records.AAAA.map((rec, idx) => (
                  <div key={idx} className="record-item">
                    <code>{rec.value}</code>
                    <span className="ttl">TTL: {rec.ttl}</span>
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'MX' && result.records.MX && (
              <div className="record-type">
                <h4>MX Records (Mail Servers)</h4>
                {result.records.MX.map((rec, idx) => (
                  <div key={idx} className="record-item">
                    <span className="priority">Priority: {rec.priority}</span>
                    <code>{rec.value}</code>
                    <span className="ttl">TTL: {rec.ttl}</span>
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'TXT' && result.records.TXT && (
              <div className="record-type">
                <h4>TXT Records</h4>
                {result.records.TXT.map((rec, idx) => (
                  <div key={idx} className="record-item">
                    <code>{rec.value}</code>
                    <span className="ttl">TTL: {rec.ttl}</span>
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'NS' && result.records.NS && (
              <div className="record-type">
                <h4>NS Records (Nameservers)</h4>
                {result.records.NS.map((rec, idx) => (
                  <div key={idx} className="record-item">
                    <code>{rec.value}</code>
                    <span className="ttl">TTL: {rec.ttl}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <p className="disclaimer">{result.disclaimer}</p>
        </div>
      )}
    </div>
  );
}
