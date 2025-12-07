export const API_URL = (() => {
  const envUrl = import.meta.env?.VITE_API_URL
  if (envUrl) {
    return envUrl.replace(/\/$/, '')
  }

  if (typeof window !== 'undefined') {
    const protocol = window.location.protocol === 'https:' ? 'https' : 'http'
    const host = window.location.hostname || 'localhost'
    return `${protocol}://${host}:8000`
  }

  return 'http://localhost:8000'
})()
