import React, { useState } from 'react';
import axios from 'axios';
import { API_URL } from '../utils/apiConfig';

export default function EmailHeaderAnalyzer() {
  const [headers, setHeaders] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleAnalyze = async () => {
    if (!headers.trim()) {
      setError('Please paste email headers');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_URL}/email/analyze-headers`, { headers });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const sampleHeaders = `From: support@example.com
To: user@company.com
Subject: Verify Your Account
Date: Mon, 8 Dec 2024 10:30:00 +0000
Received: from mail.example.com by mail.company.com
Return-Path: <support@example.com>
Authentication-Results: mail.company.com; spf=pass; dkim=pass; dmarc=pass`;

  return (
    <div className="tool-container">
      <div className="tool-header">
        <h2>📧 Email Header Analyzer</h2>
        <p>Detect spoofing, authentication issues, and phishing indicators</p>
      </div>

      <div className="tool-section">
        <label>Paste Email Headers:</label>
        <textarea
          value={headers}
          onChange={(e) => setHeaders(e.target.value)}
          placeholder="Paste raw email headers here..."
          className="email-textarea"
          rows="10"
        />

        <button
          onClick={() => setHeaders(sampleHeaders)}
          className="btn-secondary"
        >
          📝 Load Sample Headers
        </button>

        <button onClick={handleAnalyze} disabled={loading} className="btn-primary">
          {loading ? 'Analyzing...' : 'Analyze Headers'}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="result-section">
          <h3>Email Header Analysis</h3>

          <div className="email-info">
            <div className="info-row">
              <span className="label">From:</span>
              <span className="value">{result.from}</span>
            </div>
            <div className="info-row">
              <span className="label">To:</span>
              <span className="value">{result.to}</span>
            </div>
            <div className="info-row">
              <span className="label">Subject:</span>
              <span className="value">{result.subject}</span>
            </div>
            <div className="info-row">
              <span className="label">Date:</span>
              <span className="value">{result.date}</span>
            </div>
          </div>

          <div className="risk-section">
            <div className={`risk-badge ${result.risk_level}`}>
              Risk Level: <strong>{result.risk_level.toUpperCase()}</strong>
            </div>
          </div>

          <div className="auth-grid">
            <div className={`auth-card ${result.authentication.spf ? 'pass' : 'fail'}`}>
              <span className="label">SPF Authentication</span>
              <span className="status">{result.authentication.spf ? '✓ Pass' : '✗ Fail'}</span>
            </div>
            <div className={`auth-card ${result.authentication.dkim ? 'pass' : 'fail'}`}>
              <span className="label">DKIM Signature</span>
              <span className="status">{result.authentication.dkim ? '✓ Pass' : '✗ Fail'}</span>
            </div>
            <div className={`auth-card ${result.authentication.dmarc ? 'pass' : 'fail'}`}>
              <span className="label">DMARC Policy</span>
              <span className="status">{result.authentication.dmarc ? '✓ Pass' : '✗ Fail'}</span>
            </div>
            <div className="auth-card">
              <span className="label">Hops Count</span>
              <span className="value">{result.received_count}</span>
            </div>
          </div>

          {result.issues.length > 0 && (
            <div className="issues-section critical">
              <h4>🚨 Critical Issues:</h4>
              <ul className="issue-list">
                {result.issues.map((issue, idx) => (
                  <li key={idx}>{issue}</li>
                ))}
              </ul>
            </div>
          )}

          {result.warnings.length > 0 && (
            <div className="issues-section warning">
              <h4>⚠️ Warnings:</h4>
              <ul className="issue-list">
                {result.warnings.map((warning, idx) => (
                  <li key={idx}>{warning}</li>
                ))}
              </ul>
            </div>
          )}

          {result.info.length > 0 && (
            <div className="issues-section info">
              <h4>ℹ️ Information:</h4>
              <ul className="issue-list">
                {result.info.map((info, idx) => (
                  <li key={idx}>{info}</li>
                ))}
              </ul>
            </div>
          )}

          <p className="disclaimer">{result.disclaimer}</p>
        </div>
      )}
    </div>
  );
}
