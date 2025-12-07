import React from 'react'

export default function AboutPage(){
  return (
    <section className="card about-page">
      <h3>🚀 About Jayvik Labs</h3>
      
      <div className="about-content">
        <div className="founder-section">
          <div className="founder-avatar">
            <span className="avatar-icon">👨‍💻</span>
          </div>
          <div className="founder-info">
            <h4>Jaydip Jadhav</h4>
            <p className="founder-title">Founder & Ethical Hacker</p>
            <p className="founder-bio">
              Passionate cybersecurity professional dedicated to creating safe, educational environments 
              for learning ethical hacking and security fundamentals. Believes in hands-on learning 
              combined with strong ethical foundations.
            </p>
          </div>
        </div>

        <div className="mission-section">
          <h4>🎯 Our Mission</h4>
          <p>
            Jayvik Labs bridges the gap between theoretical cybersecurity knowledge and practical skills 
            through safe, simulation-based learning. We empower students, professionals, and enthusiasts 
            to understand security concepts without ever compromising real systems.
          </p>
        </div>

        <div className="values-section">
          <h4>⚖️ Our Core Values</h4>
          <div className="values-grid">
            <div className="value-card">
              <span className="value-icon">🛡️</span>
              <h5>Ethics First</h5>
              <p>Every tool, every lesson emphasizes responsible disclosure and authorized testing only.</p>
            </div>
            <div className="value-card">
              <span className="value-icon">🎓</span>
              <h5>Education Focused</h5>
              <p>Real-world scenarios in controlled environments for risk-free skill development.</p>
            </div>
            <div className="value-card">
              <span className="value-icon">🔒</span>
              <h5>Safety by Design</h5>
              <p>No real networks touched, no actual vulnerabilities exploited — pure simulation.</p>
            </div>
            <div className="value-card">
              <span className="value-icon">🌟</span>
              <h5>Practical Learning</h5>
              <p>Interactive labs that mirror industry challenges with immediate feedback.</p>
            </div>
          </div>
        </div>

        <div className="journey-section">
          <h4>📈 The Journey</h4>
          <div className="timeline">
            <div className="timeline-item">
              <span className="timeline-year">2024</span>
              <div className="timeline-content">
                <h5>Foundation</h5>
                <p>Jayvik Labs founded with vision to democratize ethical hacking education</p>
              </div>
            </div>
            <div className="timeline-item">
              <span className="timeline-year">2025</span>
              <div className="timeline-content">
                <h5>Platform Launch</h5>
                <p>Interactive cybersecurity simulator with 8+ educational modules launched</p>
              </div>
            </div>
            <div className="timeline-item">
              <span className="timeline-year">Future</span>
              <div className="timeline-content">
                <h5>Expanding Horizons</h5>
                <p>Advanced certification tracks, enterprise training, and global community building</p>
              </div>
            </div>
          </div>
        </div>

        <div className="contact-section">
          <h4>🤝 Connect With Us</h4>
          <p>
            Interested in cybersecurity education or ethical hacking training? 
            Jayvik Labs is committed to building a safer digital world through knowledge sharing.
          </p>
          <div className="contact-links">
            <button className="contact-btn">
              📧 Contact Founder
            </button>
            <button className="contact-btn">
              💼 LinkedIn
            </button>
            <button className="contact-btn">
              🌐 Portfolio
            </button>
          </div>
        </div>

        <div className="disclaimer">
          <strong>Legal Notice:</strong> Jayvik Labs provides educational cybersecurity content only. 
          Users are responsible for ensuring all activities comply with local laws and organizational policies. 
          Unauthorized testing of systems is illegal and strictly discouraged.
        </div>
      </div>
    </section>
  )
}