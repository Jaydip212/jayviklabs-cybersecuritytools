export const API_URL = (() => {
  const envUrl = import.meta.env?.VITE_API_URL
  if (envUrl) {
    return envUrl.replace(/\/$/, '')
  }

  if (typeof window !== 'undefined') {
    const protocol = window.location.protocol
    const host = window.location.hostname
    
    // Production deployment
    if (host.includes('vercel.app') || host.includes('netlify.app') || host !== 'localhost') {
      return `${protocol}//${host}/api`
    }
    
    // Local development
    return `${protocol === 'https:' ? 'https' : 'http'}://${host}:8000`
  }

  return 'http://localhost:8000'
})()

// Export as both names for compatibility
export const apiBaseURL = API_URL
export default API_URL
