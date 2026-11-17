
import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react'

import keycloak from '../keycloak'

const AuthContext = createContext(null)

const CLOUDGUARD_ROLES = [
  'IT_ADMIN',
  'SECURITY_ANALYST',
  'HR_MANAGER',
  'FINANCE_ANALYST',
]

export function AuthProvider({ children }) {
  const [authenticated, setAuthenticated] = useState(
    Boolean(keycloak.authenticated)
  )

  const [user, setUser] = useState(
    keycloak.tokenParsed || null
  )
  const sessionAuditSent = useRef(false)

  // Synchronize React state with Keycloak
  useEffect(() => {
    const syncAuthentication = () => {
  setAuthenticated(Boolean(keycloak.authenticated))
  setUser(keycloak.authenticated ? keycloak.tokenParsed : null)
}

const recordAuthenticationSession = async () => {
  if (!keycloak.authenticated || sessionAuditSent.current) {
    return
  }

  sessionAuditSent.current = true

  try {
    const response = await fetch(
      'http://localhost:8000/api/auth/session',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${keycloak.token}`,
          'Content-Type': 'application/json',
        },
      }
    )

    if (!response.ok) {
      console.error(
        'Unable to record authentication session:',
        response.status
      )
    } else {
      console.log('Authentication session recorded')
    }
  } catch (error) {
    console.error('Authentication audit request failed:', error)
  }
}

keycloak.onAuthSuccess = () => {
  syncAuthentication()
  recordAuthenticationSession()
}

keycloak.onAuthLogout = () => {
  sessionAuditSent.current = false
  syncAuthentication()
}

keycloak.onAuthRefreshSuccess = syncAuthentication

// Handle a session already authenticated during initialization
if (keycloak.authenticated) {
  recordAuthenticationSession()
}

    keycloak.onAuthRefreshError = () => {
      console.error('Keycloak token refresh failed')

      if (keycloak.isTokenExpired()) {
        setAuthenticated(false)
        setUser(null)
      }
    }

    // Handle an access token that has expired
    keycloak.onTokenExpired = async () => {
      try {
        await keycloak.updateToken(30)
        syncAuthentication()
        console.log('Access token refreshed successfully')
      } catch (error) {
        console.error('Unable to refresh access token:', error)

        if (keycloak.isTokenExpired()) {
          setAuthenticated(false)
          setUser(null)
        }
      }
    }

    // Check token validity periodically
    const refreshTimer = window.setInterval(async () => {
      if (!keycloak.authenticated) return

      try {
        const refreshed = await keycloak.updateToken(60)

        if (refreshed) {
          console.log('Access token refreshed successfully')
          syncAuthentication()
        }
      } catch (error) {
        console.error('Token refresh check failed:', error)

        if (keycloak.isTokenExpired()) {
          setAuthenticated(false)
          setUser(null)
        }
      }
    }, 30000)

    return () => {
      window.clearInterval(refreshTimer)

      keycloak.onAuthSuccess = undefined
      keycloak.onAuthLogout = undefined
      keycloak.onAuthRefreshSuccess = undefined
      keycloak.onAuthRefreshError = undefined
      keycloak.onTokenExpired = undefined
    }
  }, [])

  // Only expose CloudGuard application roles
  const roles = (
    user?.realm_access?.roles || []
  ).filter((role) => CLOUDGUARD_ROLES.includes(role))

  const login = () => keycloak.login()

const logout = async () => {
  try {
    // Refresh the token if it is close to expiry
    await keycloak.updateToken(30)

    // Record logout before ending the Keycloak session
    const response = await fetch(
      'http://localhost:8000/api/auth/logout',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${keycloak.token}`,
          'Content-Type': 'application/json',
        },
      }
    )

    if (response.ok) {
      console.log('Logout event recorded')
    } else {
      console.error(
        'Unable to record logout event:',
        response.status
      )
    }
  } catch (error) {
    console.error('Logout audit request failed:', error)
  } finally {
    // Always allow the user to log out
    await keycloak.logout({
      redirectUri: window.location.origin,
    })
  }
}


  const hasRole = (role) => roles.includes(role)

  return (
    <AuthContext.Provider
      value={{
        authenticated,
        user,
        roles,
        login,
        logout,
        hasRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)

  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider')
  }

  return context
}
