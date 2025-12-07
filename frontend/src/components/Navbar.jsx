import React from 'react'

export default function Navbar(){
  const handleExploreMore = () => {
    // This would redirect to the next page/projects section
    window.open('/projects', '_blank')
  }

  return (
    <nav className="navbar">
      <div className="brand">
        <div className="logo">🔒</div>
        <span>Jayvik Labs</span>
      </div>
      <ul className="navlinks">
        <li><a href="#home">Home</a></li>
        <li><a href="#services">Services</a></li>
        <li><a href="#testimonials">Testimonials</a></li>
        <li>
          <button 
            className="explore-btn" 
            onClick={handleExploreMore}
          >
            Explore More 🚀
          </button>
        </li>
      </ul>
    </nav>
  )
}