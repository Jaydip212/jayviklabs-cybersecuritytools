import { useState, useEffect } from 'react';
import axios from 'axios';
import { apiBaseURL } from '../utils/apiConfig';

export default function BruteForceSimulator() {
  const [targetPassword, setTargetPassword] = useState('');
  const [attackMode, setAttackMode] = useState('dictionary');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    if (loading) {
      const interval = setInterval(() => {
        setProgress((prev) => Math.min(prev + 10, 90));
      }, 100);
      return () => clearInterval(interval);
    } else {
      setProgress(0);
    }
  }, [loading]);

  const handleSimulate = async () => {
    if (!targetPassword.trim()) {
      alert('Please enter a target password');
      return;
    }

    setLoading(true);
    setProgress(0);

    try {
      const response = await axios.post(`${apiBaseURL}/security/brute-force`, {
        target_password: targetPassword,
        attack_mode: attackMode
      });
      setProgress(100);
      setResult(response.data);
    } catch (error) {
      console.error('Brute force simulation error:', error);
      alert('Simulation failed: ' + error.message);
    }

    setLoading(false);
  };

  const testPasswords = ['password', '123456', 'qwerty', 'admin', 'welcome'];

  return (
    <div className="tool-container brute-force-container">
      <h2 className="tool-title">🎯 Brute Force Simulator</h2>
      <p className="tool-description">
        Simulate password cracking attacks to understand how weak passwords are compromised.
        See time estimates and learn about different attack methods.
      </p>

      <div className="brute-section">
        <h3>🎯 Target Password</h3>
        <input
          type="text"
          value={targetPassword}
          onChange={(e) => setTargetPassword(e.target.value)}
          placeholder="Enter password to test..."
          className="text-input"
        />
        <div className="test-passwords">
          <p>Try these: </p>
          {testPasswords.map((pwd) => (
            <button key={pwd} onClick={() => setTargetPassword(pwd)} className="btn-test-pwd">
              {pwd}
            </button>
          ))}
        </div>
      </div>

      <div className="brute-section">
        <h3>⚔️ Attack Mode</h3>
        <div className="attack-mode-selector">
          <button
            className={`mode-btn ${attackMode === 'dictionary' ? 'active' : ''}`}
            onClick={() => setAttackMode('dictionary')}
          >
            📖 Dictionary Attack
          </button>
          <button
            className={`mode-btn ${attackMode === 'brute_force' ? 'active' : ''}`}
            onClick={() => setAttackMode('brute_force')}
          >
            🔨 Brute Force
          </button>
          <button
            className={`mode-btn ${attackMode === 'hybrid' ? 'active' : ''}`}
            onClick={() => setAttackMode('hybrid')}
          >
            🔀 Hybrid
          </button>
        </div>
      </div>

      <button
        onClick={handleSimulate}
        disabled={loading || !targetPassword.trim()}
        className="btn-primary"
      >
        {loading ? '⏳ Attacking...' : '🚀 Start Attack'}
      </button>

      {loading && (
        <div className="progress-container">
          <div className="progress-bar-brute">
            <div className="progress-fill-brute" style={{ width: `${progress}%` }} />
          </div>
          <p className="progress-text-brute">Attempting to crack password... {progress}%</p>
        </div>
      )}

      {result && (
        <div className="brute-results">
          <div className={`crack-status ${result.found ? 'cracked' : 'failed'}`}>
            {result.found ? '✅ PASSWORD CRACKED!' : '❌ PASSWORD NOT FOUND'}
          </div>

          <div className="results-grid-brute">
            <div className="result-card-brute">
              <h4>⏱️ Time Taken</h4>
              <p className="result-value-brute">{result.time_taken}</p>
            </div>
            <div className="result-card-brute">
              <h4>🔢 Attempts</h4>
              <p className="result-value-brute">{result.attempts.toLocaleString()}</p>
            </div>
            <div className="result-card-brute">
              <h4>📊 Success Rate</h4>
              <p className="result-value-brute">{result.success_rate}%</p>
            </div>
            <div className="result-card-brute">
              <h4>⚔️ Method</h4>
              <p className="result-value-brute">{result.attack_mode}</p>
            </div>
          </div>

          <div className="password-strength-section">
            <h3>🔐 Password Strength Analysis</h3>
            <div className="strength-grid">
              <div className="strength-item">
                <span className="strength-label">Length:</span>
                <span className="strength-value">{result.password_strength.length} characters</span>
              </div>
              <div className="strength-item">
                <span className="strength-label">Character Set:</span>
                <span className="strength-value">{result.password_strength.charset_size} possible characters</span>
              </div>
              <div className="strength-item">
                <span className="strength-label">Combinations:</span>
                <span className="strength-value">{result.password_strength.possible_combinations.toLocaleString()}</span>
              </div>
              <div className="strength-item">
                <span className="strength-label">Estimated Crack Time:</span>
                <span className="strength-value">{result.password_strength.estimated_crack_time}</span>
              </div>
            </div>
          </div>

          <div className="attack-comparison-section">
            <h3>⚔️ Attack Method Comparison</h3>
            {Object.entries(result.attack_comparison).map(([method, desc]) => (
              <div key={method} className="comparison-card">
                <h4>{method.replace('_', ' ').toUpperCase()}</h4>
                <p>{desc}</p>
              </div>
            ))}
          </div>

          <div className="prevention-section">
            <h3>🛡️ Prevention Tips</h3>
            <ul className="prevention-list">
              {result.prevention_tips.map((tip, idx) => (
                <li key={idx}>{tip}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <div className="info-section brute-info">
        <h4>📚 Understanding Brute Force Attacks</h4>
        <ul>
          <li><strong>Dictionary Attack:</strong> Tests common passwords from wordlists</li>
          <li><strong>Brute Force:</strong> Tries all possible character combinations</li>
          <li><strong>Hybrid Attack:</strong> Combines dictionary with character mutations</li>
          <li><strong>Real Attacks:</strong> Use GPUs, botnets, and distributed computing</li>
          <li><strong>Defense:</strong> Long passwords, account lockouts, rate limiting, MFA</li>
        </ul>
      </div>

      <div className="disclaimer brute-disclaimer">
        ⚠️ <strong>Educational Simulation</strong><br/>
        Real attacks are much faster with specialized hardware. Never attempt unauthorized access!
      </div>
    </div>
  );
}
