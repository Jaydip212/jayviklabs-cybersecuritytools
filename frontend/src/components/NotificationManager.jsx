import React, { useState, useEffect } from 'react'

export default function NotificationManager(){
  const [notifications, setNotifications] = useState([])

  // Function to show notification (used by other components)
  window.showNotification = (message, type = 'success', duration = 3000) => {
    const id = Date.now()
    const newNotif = {
      id,
      message,
      type // 'success', 'error', 'warning', 'info'
    }
    
    setNotifications(prev => [...prev, newNotif])
    
    if (duration > 0) {
      setTimeout(() => {
        setNotifications(prev => prev.filter(n => n.id !== id))
      }, duration)
    }
    
    return id
  }

  const removeNotification = (id) => {
    setNotifications(prev => prev.filter(n => n.id !== id))
  }

  return (
    <div className="notification-container">
      {notifications.map(notif => (
        <div
          key={notif.id}
          className={`notification notification-${notif.type}`}
        >
          <div className="notification-content">
            {notif.type === 'success' && <span>✅</span>}
            {notif.type === 'error' && <span>❌</span>}
            {notif.type === 'warning' && <span>⚠️</span>}
            {notif.type === 'info' && <span>ℹ️</span>}
            <span className="notification-message">{notif.message}</span>
          </div>
          <button
            className="notification-close"
            onClick={() => removeNotification(notif.id)}
          >
            ✕
          </button>
        </div>
      ))}
    </div>
  )
}
