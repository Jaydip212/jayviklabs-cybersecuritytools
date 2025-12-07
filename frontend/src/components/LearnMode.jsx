import React, {useMemo, useState} from 'react'

const LEARNING_POINTS = [
  {
    title: 'Why Hashing Matters',
    description: 'Hashes provide integrity checking. Modern systems use SHA-256 or stronger hashes to store passwords combined with salt.'
  },
  {
    title: 'Symmetric Encryption Basics',
    description: 'AES is widely used for secure data storage. The same key encrypts and decrypts. Protect your key with strong access controls.'
  },
  {
    title: 'Ethical Security Testing',
    description: 'Never scan networks without written permission. Use safe simulations and follow responsible disclosure policies.'
  },
  {
    title: 'Incident Response Mindset',
    description: 'Detection, containment, eradication, recovery, and lessons learned. Documentation is critical for improving defenses.'
  }
]

const OWASP_TOP10 = [
  {
    id: 'A01',
    name: 'Broken Access Control',
    risk: 'Critical',
    summary: 'Missing or flawed authorization checks let attackers access data or features they should not.',
    mitigation: 'Enforce least privilege, audit access paths, and deny by default.'
  },
  {
    id: 'A02',
    name: 'Cryptographic Failures',
    risk: 'High',
    summary: 'Weak or missing encryption exposes sensitive data in transit or at rest.',
    mitigation: 'Use modern algorithms (TLS 1.3, AES-256) and manage keys securely.'
  },
  {
    id: 'A03',
    name: 'Injection',
    risk: 'High',
    summary: 'Untrusted input inside queries or commands lets attackers run malicious code.',
    mitigation: 'Use parameterized queries and strict input validation.'
  },
  {
    id: 'A04',
    name: 'Insecure Design',
    risk: 'High',
    summary: 'Missing security controls in the system blueprint lead to exploitable gaps.',
    mitigation: 'Threat model early, add security requirements, and review designs.'
  },
  {
    id: 'A05',
    name: 'Security Misconfiguration',
    risk: 'High',
    summary: 'Default credentials, verbose errors, or open cloud storage expose systems.',
    mitigation: 'Harden baselines, automate configuration checks, and remove unused services.'
  },
  {
    id: 'A06',
    name: 'Vulnerable & Outdated Components',
    risk: 'High',
    summary: 'Libraries with known CVEs give attackers ready-made exploits.',
    mitigation: 'Maintain SBOMs, patch quickly, and monitor advisories.'
  },
  {
    id: 'A07',
    name: 'Identification & Auth Failures',
    risk: 'High',
    summary: 'Weak login flows, credential stuffing, or missing MFA enable account takeover.',
    mitigation: 'Add MFA, rate-limit logins, and monitor for brute force attempts.'
  },
  {
    id: 'A08',
    name: 'Software & Data Integrity Failures',
    risk: 'High',
    summary: 'Untrusted pipelines or tampered data can introduce backdoors.',
    mitigation: 'Sign releases, validate dependencies, and enforce integrity checks.'
  },
  {
    id: 'A09',
    name: 'Security Logging & Monitoring Failures',
    risk: 'Medium',
    summary: 'Missing logs or alerting allows attacks to go undetected.',
    mitigation: 'Centralize logs, tune detections, and rehearse incident response.'
  },
  {
    id: 'A10',
    name: 'Server-Side Request Forgery (SSRF)',
    risk: 'Medium',
    summary: 'Abused servers fetch attacker-controlled URLs, exposing internal services.',
    mitigation: 'Validate outbound destinations and restrict metadata/network access.'
  }
]

const OWASP_QUIZ = [
  {
    prompt: 'A user discovers they can change their account ID in the URL and view another profile. Which OWASP risk is this?',
    answers: [
      { text: 'A01 — Broken Access Control', correct: true },
      { text: 'A05 — Security Misconfiguration', correct: false },
      { text: 'A09 — Logging & Monitoring Failures', correct: false }
    ],
    tip: 'Access control must be enforced on the server, regardless of user input.'
  },
  {
    prompt: 'Your API still accepts MD5 hashed passwords. Which OWASP category should you flag?',
    answers: [
      { text: 'A02 — Cryptographic Failures', correct: true },
      { text: 'A03 — Injection', correct: false },
      { text: 'A07 — Identification & Auth Failures', correct: false }
    ],
    tip: 'Modern password storage requires adaptive hashing like bcrypt or Argon2.'
  },
  {
    prompt: 'The CI pipeline downloads build scripts from an unauthenticated URL. What risk does this illustrate?',
    answers: [
      { text: 'A08 — Software & Data Integrity Failures', correct: true },
      { text: 'A06 — Vulnerable & Outdated Components', correct: false },
      { text: 'A10 — Server-Side Request Forgery', correct: false }
    ],
    tip: 'Supply-chain integrity needs signed artifacts and trusted sources.'
  }
]

export default function LearnMode(){
  const [selectedControl, setSelectedControl] = useState(OWASP_TOP10[0])
  const [quizIndex, setQuizIndex] = useState(0)
  const [selectedAnswer, setSelectedAnswer] = useState(null)
  const [score, setScore] = useState(0)
  const [showFeedback, setShowFeedback] = useState(false)

  const currentQuestion = useMemo(() => OWASP_QUIZ[quizIndex], [quizIndex])

  const handleAnswer = (answer) => {
    if (showFeedback) return
    setSelectedAnswer(answer)
    setShowFeedback(true)
    if (answer.correct) {
      setScore((prev) => prev + 1)
    }
  }

  const nextQuestion = () => {
    setShowFeedback(false)
    setSelectedAnswer(null)
    if (quizIndex < OWASP_QUIZ.length - 1) {
      setQuizIndex((prev) => prev + 1)
    } else {
      setQuizIndex(0)
      setScore(0)
    }
  }

  return (
    <section className="card learn-mode">
      <h3>📘 Learn Mode</h3>
      <p className="card-description">Quick lessons for cybersecurity beginners</p>
      <div className="learning-grid">
        {LEARNING_POINTS.map((point, index) => (
          <div key={index} className="learning-card">
            <h4>{point.title}</h4>
            <p>{point.description}</p>
          </div>
        ))}
      </div>

      <div className="owasp-section">
        <div className="owasp-header">
          <h4>OWASP Top 10 Quick Reference</h4>
          <p className="owasp-subtitle">Tap a risk to view the high-level mitigation strategy.</p>
        </div>
        <div className="owasp-grid">
          {OWASP_TOP10.map((item) => (
            <button
              key={item.id}
              className={`owasp-card ${selectedControl.id === item.id ? 'active' : ''}`}
              onClick={() => setSelectedControl(item)}
            >
              <span className="owasp-id">{item.id}</span>
              <span className="owasp-name">{item.name}</span>
              <span className={`owasp-risk risk-${item.risk.toLowerCase()}`}>{item.risk}</span>
            </button>
          ))}
        </div>
        <div className="owasp-details">
          <h5>{selectedControl.name}</h5>
          <p className="owasp-summary">{selectedControl.summary}</p>
          <p className="owasp-mitigation"><strong>Mitigation:</strong> {selectedControl.mitigation}</p>
        </div>
      </div>

      <div className="owasp-quiz">
        <div className="quiz-header">
          <h4>OWASP Lightning Quiz</h4>
          <span className="quiz-progress">Score: {score} / {OWASP_QUIZ.length}</span>
        </div>
        <p className="quiz-question">{currentQuestion.prompt}</p>
        <div className="quiz-options">
          {currentQuestion.answers.map((answer, index) => (
            <button
              key={index}
              className={`quiz-option ${selectedAnswer === answer ? (answer.correct ? 'correct' : 'incorrect') : ''}`}
              onClick={() => handleAnswer(answer)}
              disabled={showFeedback}
            >
              {answer.text}
            </button>
          ))}
        </div>
        {showFeedback && selectedAnswer && (
          <div className={`quiz-feedback ${selectedAnswer.correct ? 'correct' : 'incorrect'}`}>
            <strong>{selectedAnswer.correct ? 'Correct!' : 'Not quite.'}</strong>
            <p>{currentQuestion.tip}</p>
            <button className="next-btn" onClick={nextQuestion}>
              {quizIndex === OWASP_QUIZ.length - 1 ? 'Restart Quiz' : 'Next Question'}
            </button>
          </div>
        )}
      </div>

      <div className="disclaimer">
        ⚠️ Educational use only — no real networks are touched. Practice ethical security habits at all times.
      </div>
      <a className="explore-link" href="/projects" target="_blank" rel="noopener noreferrer" id="explore-btn">
        Explore More 🚀
      </a>
    </section>
  )
}