import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import keycloak from './keycloak.js'
import { AuthProvider } from './auth/AuthContext.jsx'

async function startApp() {
  try {
    await keycloak.init({
      onLoad: 'check-sso',
      pkceMethod: 'S256',
      checkLoginIframe: false,
    })

    console.log('Keycloak initialized')
    console.log('Authenticated:', keycloak.authenticated)

    createRoot(document.getElementById('root')).render(
      <StrictMode>
        <AuthProvider>
          <App />
        </AuthProvider>
      </StrictMode>,
    )
  } catch (error) {
    console.error('Keycloak initialization failed:', error)

    document.getElementById('root').innerHTML =
      '<h2>Authentication service unavailable. Please try again later.</h2>'
  }
}

startApp()