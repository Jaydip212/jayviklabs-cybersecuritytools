import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { API_URL } from '../utils/apiConfig'

export default function LearningHub(){
  const [resources, setResources] = useState(null)
  const [loading, setLoading] = useState(true)
  const [selectedCategory, setSelectedCategory] = useState(null)
  const [expandedTutorial, setExpandedTutorial] = useState(null)

  useEffect(() => {
    fetchResources()
  }, [])

  const fetchResources = async () => {
    try {
      const response = await axios.get(`${API_URL}/learning/resources`)
      setResources(response.data)
      if (response.data.resources.length > 0) {
        setSelectedCategory(response.data.resources[0].category)
      }
    } catch (error) {
      console.error('Error fetching learning resources:', error)
    } finally {
      setLoading(false)
    }
  }

  const getLevelBadgeColor = (level) => {
    const colors = {
      'Beginner': '#22c55e',
      'Intermediate': '#f97316',
      'Advanced': '#ef4444',
      'Expert': '#9c6eff'
    }
    return colors[level] || '#39ff14'
  }

  if (loading) {
    return <section className="learning-container card"><p>Loading resources...</p></section>
  }

  if (!resources) {
    return <section className="learning-container card"><p>Failed to load resources</p></section>
  }

  const selectedCategoryData = resources.resources.find(r => r.category === selectedCategory)

  return (
    <section className="learning-container card">
      <h2>📚 Learning Hub</h2>
      <p className="learning-intro">Master cybersecurity through interactive tutorials, best practices, and certification paths</p>

      <div className="learning-layout">
        {/* Sidebar - Categories */}
        <div className="learning-sidebar">
          <h3>📂 Categories</h3>
          <div className="category-list">
            {resources.resources.map((resource, idx) => (
              <button
                key={idx}
                className={`category-btn ${selectedCategory === resource.category ? 'active' : ''}`}
                onClick={() => setSelectedCategory(resource.category)}
              >
                {resource.category}
              </button>
            ))}
          </div>

          {/* Best Practices */}
          <div className="practices-section">
            <h3>✅ Best Practices</h3>
            <div className="practice-tabs">
              <details>
                <summary>🔐 Authentication</summary>
                <ul>
                  {resources.best_practices.authentication.map((practice, idx) => (
                    <li key={idx}>{practice}</li>
                  ))}
                </ul>
              </details>
              <details>
                <summary>🔒 Data Protection</summary>
                <ul>
                  {resources.best_practices.data_protection.map((practice, idx) => (
                    <li key={idx}>{practice}</li>
                  ))}
                </ul>
              </details>
              <details>
                <summary>🌐 Web Apps</summary>
                <ul>
                  {resources.best_practices.web_applications.map((practice, idx) => (
                    <li key={idx}>{practice}</li>
                  ))}
                </ul>
              </details>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="learning-main">
          {selectedCategoryData && (
            <div className="category-content">
              <h3>{selectedCategoryData.category}</h3>
              <div className="tutorials-grid">
                {selectedCategoryData.tutorials.map((tutorial, idx) => (
                  <div key={idx} className="tutorial-card">
                    <div 
                      className="tutorial-header"
                      onClick={() => setExpandedTutorial(expandedTutorial === idx ? null : idx)}
                    >
                      <h4>{tutorial.title}</h4>
                      <span className="expand-icon">{expandedTutorial === idx ? '▼' : '▶'}</span>
                    </div>
                    <div className="tutorial-meta">
                      <span className="duration">⏱️ {tutorial.duration}</span>
                      <span 
                        className="level-badge"
                        style={{backgroundColor: getLevelBadgeColor(tutorial.level)}}
                      >
                        {tutorial.level}
                      </span>
                    </div>
                    <p className="tutorial-description">{tutorial.description}</p>
                    
                    {expandedTutorial === idx && (
                      <div className="tutorial-expanded">
                        <h5>Topics Covered:</h5>
                        <div className="topics-grid">
                          {tutorial.topics.map((topic, tidx) => (
                            <span key={tidx} className="topic-tag">
                              {topic}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Security Mindset */}
          <div className="mindset-section">
            <h3>🧠 Security Mindset</h3>
            <div className="mindset-grid">
              {resources.security_mindset.map((principle, idx) => (
                <div key={idx} className="mindset-card">
                  <span className="mindset-number">{idx + 1}</span>
                  <p>{principle}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Certifications */}
          <div className="certifications-section">
            <h3>🎓 Recommended Certifications</h3>
            <div className="cert-grid">
              {resources.certifications.map((cert, idx) => (
                <div key={idx} className="cert-card">
                  <h4>{cert.name}</h4>
                  <p className="cert-duration">📅 {cert.duration}</p>
                  <p className="cert-difficulty">
                    Level: <span style={{color: getLevelBadgeColor(cert.difficulty)}}>{cert.difficulty}</span>
                  </p>
                  <div className="cert-topics">
                    {cert.topics.map((topic, tidx) => (
                      <span key={tidx} className="cert-topic">{topic}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Learning Paths */}
          <div className="learning-paths-section">
            <h3>🛤️ Learning Paths</h3>
            <div className="paths-grid">
              {Object.entries(resources.learning_path).map(([level, topics], idx) => (
                <div key={idx} className="path-card">
                  <h4>{level.toUpperCase()}</h4>
                  <ol>
                    {topics.map((topic, tidx) => (
                      <li key={tidx}>{topic}</li>
                    ))}
                  </ol>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="learning-disclaimer">
        <p>💡 <strong>Tip:</strong> Start with Beginner level tutorials and progress to Intermediate and Advanced as you build confidence!</p>
      </div>
    </section>
  )
}
