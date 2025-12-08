import React, { useState } from 'react'

export default function Navbar(){
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('jayvik_theme');
    return saved || 'dark';
  });

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    localStorage.setItem('jayvik_theme', newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
  };

  const scrollToSection = (sectionId) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleExploreMore = () => {
    scrollToSection('services');
  }

  return (
    <nav className="navbar">
      <div className="brand">
        <div className="logo">🔒</div>
        <span>Jayvik Labs</span>
      </div>
      <ul className="navlinks">
        <li><a href="#home" onClick={() => scrollToSection('home')}>🏠 Home</a></li>
        <li><a href="#services" onClick={() => scrollToSection('services')}>⚙️ Tools</a></li>
        <li><a href="#testimonials" onClick={() => scrollToSection('testimonials')}>💬 Reviews</a></li>
        <li><a href="#about" onClick={() => scrollToSection('about')}>ℹ️ About</a></li>
        <li>
          <button 
            className="theme-toggle-btn" 
            onClick={toggleTheme}
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Theme`}
          >
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
        </li>
        <li>
          <button 
            className="explore-btn" 
            onClick={handleExploreMore}
          >
            🚀 Explore
          </button>
        </li>
      </ul>
    </nav>
  )
}