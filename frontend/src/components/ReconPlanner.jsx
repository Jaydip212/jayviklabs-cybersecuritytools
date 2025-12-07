import React, {useState} from 'react'
import axios from 'axios'
import { API_URL } from '../utils/apiConfig'

export default function ReconPlanner(){
  const [target, setTarget] = useState('app.example.com')
  const [plan, setPlan] = useState(null)
  const [loading, setLoading] = useState(false)

  const generatePlan = async () => {
    if (!target.trim()) return
    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/recon/blueprint`, { target })
      setPlan(response.data)
    } catch (error) {
      console.error('Recon blueprint failed:', error)
      setPlan({
        error: 'Simulation failed. Ensure the backend is reachable.'
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="card">
      <h3>🧭 Recon Blueprint Planner</h3>
      <p className="card-description">
        Build a safe reconnaissance checklist for ethical hacking engagements.
      </p>

      <div className="input-group">
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="Enter target label (simulation only)..."
          className="text-input"
        />
        <button
          onClick={generatePlan}
          disabled={loading || !target.trim()}
          className="scan-btn"
        >
          {loading ? 'Generating...' : 'Generate Blueprint'}
        </button>
      </div>

      {plan && !plan.error && (
        <div className="result-panel">
          <div className="recon-summary">
            <h4>Engagement Focus — {plan.profile}</h4>
            <p>Target: <code>{plan.target}</code></p>
            <div className="focus-tags">
              {plan.focus_areas.map((area, index) => (
                <span key={index} className="focus-tag">{area}</span>
              ))}
            </div>
          </div>

          <div className="playbook">
            <h4>High-Level Playbook</h4>
            <ol>
              {plan.playbook.map((step, index) => (
                <li key={index}>{step}</li>
              ))}
            </ol>
          </div>

          <div className="recon-phases">
            {plan.recommended_phases.map((phase, index) => (
              <div key={index} className="phase-card">
                <h5>{phase.phase}</h5>
                <div className="phase-section">
                  <strong>Tasks:</strong>
                  <ul>
                    {phase.tasks.map((task, tIndex) => (
                      <li key={tIndex}>{task}</li>
                    ))}
                  </ul>
                </div>
                <div className="phase-section">
                  <strong>Suggested Tools:</strong>
                  <div className="tool-chips">
                    {phase.tools.map((tool, toolIndex) => (
                      <span key={toolIndex} className="tool-chip">{tool}</span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="disclaimer">
            <p><strong>{plan.disclaimer}</strong></p>
            <ul>
              {plan.ethics.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {plan && plan.error && (
        <div className="error-panel">
          <p>{plan.error}</p>
        </div>
      )}

      <div className="info-box">
        <h4>Ethical Recon Tips:</h4>
        <ul>
          <li>Stick strictly to the authorized scope and time window.</li>
          <li>Capture findings responsibly with timestamps and reproducible evidence.</li>
          <li>Coordinate with stakeholders before escalating any discovery.</li>
        </ul>
      </div>
    </section>
  )
}
