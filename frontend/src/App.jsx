import React from 'react'
import Navbar from './components/Navbar'
import PasswordAnalyzer from './components/PasswordAnalyzer'
import PortSimulator from './components/PortSimulator'
import HashDemo from './components/HashDemo'
import CryptoLab from './components/CryptoLab'
import ThreatSimulator from './components/ThreatSimulator'
import LearnMode from './components/LearnMode'
import PhishingAnalyzer from './components/PhishingAnalyzer'
import ReconPlanner from './components/ReconPlanner'
import NmapSimulator from './components/NmapSimulator'
import DnsEnumerator from './components/DnsEnumerator'
import SslAnalyzer from './components/SslAnalyzer'
import SubdomainEnumerator from './components/SubdomainEnumerator'
import WhoisLookup from './components/WhoisLookup'
import AboutPage from './components/AboutPage'

export default function App(){
  return (
    <div className="app-root" id="home">
      <Navbar />
      <main className="container">
        <header className="hero">
          <div>
            <h1>Jayvik Labs — Cybersecurity Educational Playground</h1>
            <p className="lead">Interactive simulations to learn cybersecurity fundamentals safely. No real networks are touched — every test runs in an isolated demo lab.</p>
          </div>
          <div className="hero-metrics" id="services">
            <div className="metric-card">
              <span className="metric-value">100% Simulated</span>
              <span className="metric-label">Safe Training</span>
            </div>
            <div className="metric-card">
              <span className="metric-value">12 Labs</span>
              <span className="metric-label">Interactive Modules</span>
            </div>
            <div className="metric-card">
              <span className="metric-value">⚠️</span>
              <span className="metric-label">Ethical-Only</span>
            </div>
          </div>
        </header>

        <div className="grid">
          <PasswordAnalyzer />
          <PortSimulator />
          <HashDemo />
          <CryptoLab />
          <PhishingAnalyzer />
          <ReconPlanner />
          <ThreatSimulator />
          <NmapSimulator />
          <DnsEnumerator />
          <SslAnalyzer />
          <SubdomainEnumerator />
          <WhoisLookup />
        </div>

        <section id="testimonials" className="testimonials">
          <h3>What Students Say</h3>
          <div className="testimonial-grid">
            <blockquote>
              "Jayvik Labs made learning ethical hacking approachable and safe!" <span>- Security Bootcamp Student</span>
            </blockquote>
            <blockquote>
              "The port scanner demo helped me understand Nmap concepts without touching real networks." <span>- SOC Analyst Intern</span>
            </blockquote>
            <blockquote>
              "Love the encryption lab — super easy to grasp AES basics." <span>- CS Undergraduate</span>
            </blockquote>
          </div>
        </section>

        <LearnMode />
        <AboutPage />
      </main>
      <footer className="footer">
        © {new Date().getFullYear()} Jayvik Labs — Educational use only. Practice ethical cybersecurity.
      </footer>
    </div>
  )
}