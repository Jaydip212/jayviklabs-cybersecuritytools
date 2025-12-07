import React, { useState } from 'react';
import axios from 'axios';
import { API_URL } from '../utils/apiConfig';

export default function NmapSimulator() {
  const [target, setTarget] = useState('example.com');
  const [scanType, setScanType] = useState('syn');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_URL}/nmap/scan`, {
        target,
        scan_type: scanType
      });
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
        <h2>🔍 Nmap Simulator</h2>
        <p>Simulate port scanning on fictional networks (Educational Only)</p>
      </div>

      <div className="tool-section">
        <label>Target Host/Domain:</label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com or 192.168.1.1"
        />

        <label>Scan Type:</label>
        <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
          <option value="syn">SYN Scan (-sS)</option>
          <option value="connect">Connect Scan (-sT)</option>
          <option value="udp">UDP Scan (-sU)</option>
          <option value="ack">ACK Scan (-sA)</option>
        </select>

        <button onClick={handleScan} disabled={loading} className="btn-primary">
          {loading ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="result-section">
          <h3>Scan Results</h3>
          <p className="scan-meta">
            <strong>Target:</strong> {result.target} | <strong>Type:</strong> {result.scan_type} | <strong>Time:</strong> {result.scan_time}
          </p>

          <div className="ports-summary">
            <div className="summary-box">
              <span className="label">Open Ports</span>
              <span className="value">{result.open_ports.length}</span>
            </div>
            <div className="summary-box">
              <span className="label">Closed Ports</span>
              <span className="value">{result.closed_ports}</span>
            </div>
          </div>

          {result.open_ports.length > 0 && (
            <table className="ports-table">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Service</th>
                  <th>State</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {result.open_ports.map((port, idx) => (
                  <tr key={idx}>
                    <td className="port-num">{port.port}</td>
                    <td>{port.service}</td>
                    <td className="state-open">{port.state}</td>
                    <td className="reason">{port.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <p className="disclaimer">{result.disclaimer}</p>
        </div>
      )}
    </div>
  );
}
