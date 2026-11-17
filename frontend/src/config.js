// Public browser-side API configuration.
// Set VITE_API_BASE_URL at build time for production.
// An empty value uses same-origin routes (for example, https://cloudguard.example/api).
const configuredApiBase = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

export const API_BASE_URL = configuredApiBase.replace(/\/+$/, '')
