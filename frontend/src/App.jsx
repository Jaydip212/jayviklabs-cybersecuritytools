import React, { useState, useEffect } from 'react'
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
import PasswordGenerator from './components/PasswordGenerator'
import EmailHeaderAnalyzer from './components/EmailHeaderAnalyzer'
import SqlInjectionLab from './components/SqlInjectionLab'
import SteganographyTool from './components/SteganographyTool'
import HashingCracker from './components/HashingCracker'
import VulnerabilityScanner from './components/VulnerabilityScanner'
import XssTester from './components/XssTester'
import BruteForceSimulator from './components/BruteForceSimulator'
import MobileSecurityChecker from './components/MobileSecurityChecker'
import ApiSecurityAnalyzer from './components/ApiSecurityAnalyzer'
import CsrfTokenGenerator from './components/CsrfTokenGenerator'
import LogAnalyzer from './components/LogAnalyzer'
import UrlSecurityChecker from './components/UrlSecurityChecker'
import LearningHub from './components/LearningHub'
import NotificationManager from './components/NotificationManager'
import AboutPage from './components/AboutPage'

export default function App(){
  const [achievements, setAchievements] = useState(() => {
    const saved = localStorage.getItem('jayvik_achievements');
    return saved ? JSON.parse(saved) : {
      xp: 0,
      level: 1,
      tools_used: 0,
      badges: []
    };
  });

  useEffect(() => {
    localStorage.setItem('jayvik_achievements', JSON.stringify(achievements));
  }, [achievements]);

  const addXP = (points = 10) => {
    setAchievements(prev => {
      const newXP = prev.xp + points;
      const newLevel = Math.floor(newXP / 100) + 1;
      return { ...prev, xp: newXP, level: newLevel };
    });
  };

  return (
    <div className="app-root" id="home">
      <NotificationManager />
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
              <span className="metric-value">25 Labs</span>
              <span className="metric-label">Interactive Modules</span>
            </div>
            <div className="metric-card">
              <span className="metric-value">⚠️</span>
              <span className="metric-label">Ethical-Only</span>
            </div>
            <div className="metric-card gamer">
              <span className="metric-value">Lvl {achievements.level}</span>
              <span className="metric-label">XP: {achievements.xp}</span>
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
          <PasswordGenerator />
          <EmailHeaderAnalyzer />
          <SqlInjectionLab />
          <SteganographyTool />
          <HashingCracker />
          <VulnerabilityScanner />
          <XssTester />
          <BruteForceSimulator />
          <MobileSecurityChecker />
          <ApiSecurityAnalyzer />
          <CsrfTokenGenerator />
          <LogAnalyzer />
          <UrlSecurityChecker />
        </div>

        <LearningHub />

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