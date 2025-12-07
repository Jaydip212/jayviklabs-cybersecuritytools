import React, {useState} from 'react'

const SCENARIOS = [
  {
    id: 1,
    title: 'Failed Logins Surge',
    description: 'Your detection system shows 50 failed SSH login attempts from a single IP within 5 minutes. What should you do?',
    options: [
      { text: 'Ignore it and hope it stops', correct: false, explanation: 'Attackers often try brute-force for hours. Ignoring risks compromise.' },
      { text: 'Block the IP and investigate logs', correct: true, explanation: 'Immediate action and analysis are key to respond to brute-force attempts.' },
      { text: 'Restart the server immediately', correct: false, explanation: 'Rebooting does not address the attack source or prevent future attempts.' }
    ]
  },
  {
    id: 2,
    title: 'Suspicious Outbound Traffic',
    description: 'A workstation begins making outbound connections to unknown IP addresses on port 4444. Next step?',
    options: [
      { text: 'Quarantine the device and inspect', correct: true, explanation: 'This stops potential malware from spreading while you investigate.' },
      { text: 'Disable the firewall to see more traffic', correct: false, explanation: 'This opens more exposure and can worsen the problem.' },
      { text: 'Close your SOC dashboard', correct: false, explanation: 'Reducing visibility prevents you from responding effectively.' }
    ]
  },
  {
    id: 3,
    title: 'Ransomware Alert',
    description: 'Your EDR flags suspicious encryption activity on a file server. Best action?',
    options: [
      { text: 'Disconnect the server from the network', correct: true, explanation: 'This prevents ransomware from spreading while you respond.' },
      { text: 'Pay the ransom immediately', correct: false, explanation: 'Paying encourages attackers and does not guarantee restoration.' },
      { text: 'Delete all system logs', correct: false, explanation: 'Logs are vital for investigation and legal purposes.' }
    ]
  }
]

export default function ThreatSimulator(){
  const [currentStep, setCurrentStep] = useState(0)
  const [selectedOption, setSelectedOption] = useState(null)
  const [score, setScore] = useState(0)
  const [showExplanation, setShowExplanation] = useState(false)

  const scenario = SCENARIOS[currentStep]

  const handleOptionSelect = (option) => {
    setSelectedOption(option)
    setShowExplanation(true)

    if (option.correct) {
      setScore(prev => prev + 1)
    }
  }

  const nextScenario = () => {
    setSelectedOption(null)
    setShowExplanation(false)
    if (currentStep < SCENARIOS.length - 1) {
      setCurrentStep(prev => prev + 1)
    }
  }

  const restartQuiz = () => {
    setCurrentStep(0)
    setSelectedOption(null)
    setScore(0)
    setShowExplanation(false)
  }

  return (
    <section className="card" id="threat-simulator">
      <h3>🛡️ Threat Detection Simulator</h3>
      <p className="card-description">
        Practice incident response decisions in a safe environment
      </p>

      <div className="score-card">Progress: {score} / {SCENARIOS.length}</div>

      <div className="scenario-card">
        {scenario ? (
          <>
            <h4>{scenario.title}</h4>
            <p>{scenario.description}</p>
            <div className="options-grid">
              {scenario.options.map((option, index) => (
                <button
                  key={index}
                  className={`option-btn ${selectedOption === option ? (option.correct ? 'correct' : 'incorrect') : ''}`}
                  onClick={() => !showExplanation && handleOptionSelect(option)}
                  disabled={showExplanation}
                >
                  {option.text}
                </button>
              ))}
            </div>

            {showExplanation && selectedOption && (
              <div className={`explanation ${selectedOption.correct ? 'correct' : 'incorrect'}`}>
                <strong>{selectedOption.correct ? 'Great response! ✅' : 'Let\'s rethink that.'}</strong>
                <p>{selectedOption.explanation}</p>
                <button className="next-btn" onClick={nextScenario}>
                  {currentStep === SCENARIOS.length - 1 ? 'View Results' : 'Next Scenario'}
                </button>
              </div>
            )}
          </>
        ) : (
          <div className="summary-card">
            <h4>Simulation Complete! 🎉</h4>
            <p>You scored {score} out of {SCENARIOS.length}.</p>
            <ul>
              <li>Always respond quickly to suspicious activity.</li>
              <li>Quarantining affected systems keeps threats contained.</li>
              <li>Document actions for post-incident review.
              </li>
            </ul>
            <button className="restart-btn" onClick={restartQuiz}>
              Run Simulation Again
            </button>
          </div>
        )}
      </div>
    </section>
  )
}