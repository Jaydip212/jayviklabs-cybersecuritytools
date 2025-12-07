import React, {useState} from 'react'
import axios from 'axios'
import { API_URL } from '../utils/apiConfig'

export default function PortSimulator(){
  const [target, setTarget] = useState('example.local')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const runPortScan = async () => {
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/port-scan`, {
        target: target
      })
      setResult(response.data)
    } catch (error) {
      console.error('Port scan simulation failed:', error)
      setResult({
        error: 'Simulation failed. Make sure the backend is running.'
      })
    } finally {
      setLoading(false)
    }
  }

  const getPortStateColor = (state) => {
    const colors = {
      'open': '#28a745',
      'closed': '#dc3545', 
      'filtered': '#ffc107'
    }
    return colors[state] || '#6c757d'
  }

  const getPortStateIcon = (state) => {
    const icons = {
      'open': '🟢',
      'closed': '🔴',
      'filtered': '🟡'
    }
    return icons[state] || '⚪'
  }

  return (
    <section className="card">
      <h3>🔍 Port Scan Simulator (SAFE)</h3>
      <p className="card-description">
        Simulate network port scanning for educational purposes only
      </p>
      
      <div className="warning-banner">
        <strong>⚠️ SIMULATION ONLY</strong> - No real network scanning is performed
      </div>

      <div className="input-group">
        <input 
          type="text"
          value={target} 
          onChange={(e) => setTarget(e.target.value)}
          placeholder="Enter target (simulation only)..."
          className="target-input"
        />
        <button 
          onClick={runPortScan}
          disabled={loading}
          className="scan-btn"
        >
          {loading ? 'Scanning...' : 'Run Simulation'}
        </button>
      </div>

      {result && !result.error && (
        <div className="result-panel">
          <div className="scan-header">
            <h4>Scan Results for {result.hostname}</h4>
            <div className="target-info">
              <div>Requested: <code>{result.target_requested}</code></div>
              <div>Simulated Target: <code>{result.target_simulated}</code></div>
              <div>Scan Type: {result.scan_type}</div>
              <div>Scan Time: {result.scan_time}</div>
            </div>
          </div>

          <div className="ports-table">
            <h4>Port Status:</h4>
            <table>
              <thead>
                <tr>
                  <th>Port</th>
                  <th>State</th>
                  <th>Service</th>
                </tr>
              </thead>
              <tbody>
                {result.results.map((port, index) => (
                  <tr key={index}>
                    <td>{port.port}</td>
                    <td>
                      <span 
                        className="port-state"
                        style={{ color: getPortStateColor(port.state) }}
                      >
                        {getPortStateIcon(port.state)} {port.state}
                      </span>
                    </td>
                    <td>{port.service}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="disclaimer">
            <p><strong>{result.disclaimer}</strong></p>
            <p><em>{result.educational_note}</em></p>
          </div>
        </div>
      )}

      {result && result.error && (
        <div className="error-panel">
          <p>{result.error}</p>
        </div>
      )}

      <div className="info-box">
        <h4>Port Scanning Ethics:</h4>
        <ul>
          <li><strong>Always get permission</strong> before scanning networks</li>
          <li>Only scan systems you own or have explicit authorization to test</li>
          <li>Port scanning without permission is illegal in many jurisdictions</li>
          <li>Use tools like Nmap only in controlled, authorized environments</li>
          <li>This simulator provides safe learning without legal risks</li>
        </ul>
      </div>
    </section>
  )
}