
import { useState, useEffect } from 'react'

import { useAuth } from './auth/AuthContext'
import { canAccess } from './auth/permissions'
import keycloak from './keycloak'

import './App.css'


const RBAC_ENDPOINTS = [
  {
    name: 'IT Administration',
    path: '/api/admin/users',
    roles: ['IT_ADMIN'],
  },
  {
    name: 'Security Policies',
    path: '/api/security/policies',
    roles: ['IT_ADMIN', 'SECURITY_ANALYST'],
  },
  {
    name: 'Security Operations',
    path: '/api/security/events',
    roles: ['IT_ADMIN', 'SECURITY_ANALYST'],
  },
  {
    name: 'HR Dashboard',
    path: '/api/hr/dashboard',
    roles: ['HR_MANAGER'],
  },
  {
    name: 'Finance Dashboard',
    path: '/api/finance/dashboard',
    roles: ['FINANCE_ANALYST'],
  },
]

function App() {
  const {
    authenticated,
    user,
    roles,
    login,
    logout,
  } = useAuth()

  const [apiResult, setApiResult] = useState(null)
  const [apiLoading, setApiLoading] = useState(false)
  const [usersError, setUsersError] = useState(null)

  const [newUser, setNewUser] = useState({
  username: '',
  email: '',
  first_name: '',
  last_name: '',
  department_id: '1',
  temporary_password: '',
})

const [creatingUser, setCreatingUser] = useState(false)
const [createUserMessage, setCreateUserMessage] = useState(null)

  const [rbacResults, setRbacResults] = useState([])
  const [rbacLoading, setRbacLoading] = useState(false)
  const [userLookupId, setUserLookupId] = useState('1')
  const [userLookupResult, setUserLookupResult] = useState(null)
  const [userLookupLoading, setUserLookupLoading] = useState(false)
  const [usersList, setUsersList] = useState([])
  const [usersLoading, setUsersLoading] = useState(false)
  const [editingUser, setEditingUser] = useState(null)
  const [updatingUser, setUpdatingUser] = useState(false)
  const [updateUserMessage, setUpdateUserMessage] = useState(null)

  const [auditEvents, setAuditEvents] = useState([])
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditError, setAuditError] = useState(null)

  const [securityPolicies, setSecurityPolicies] = useState([])
  const [policiesLoading, setPoliciesLoading] = useState(false)
  const [policiesError, setPoliciesError] = useState(null)
  const [policyMessage, setPolicyMessage] = useState(null)
  const [savingPolicy, setSavingPolicy] = useState(false)
  const [editingPolicyId, setEditingPolicyId] = useState(null)
  const [policyForm, setPolicyForm] = useState({
    name: '',
    description: '',
    category: 'IAM',
    severity: 'MEDIUM',
    is_enabled: true,
  })


  const [riskAssessments, setRiskAssessments] = useState([])
  const [risksLoading, setRisksLoading] = useState(false)
  const [risksError, setRisksError] = useState(null)
  const [riskMessage, setRiskMessage] = useState(null)
  const [savingRisk, setSavingRisk] = useState(false)
  const [editingRiskId, setEditingRiskId] = useState(null)
  const [riskForm, setRiskForm] = useState({
    title: '',
    description: '',
    asset: '',
    category: 'CLOUD_INFRASTRUCTURE',
    likelihood: 3,
    impact: 3,
    status: 'OPEN',
    mitigation_plan: '',
    owner: '',
  })

  const canViewAuditEvents =
    roles.includes('IT_ADMIN') || roles.includes('SECURITY_ANALYST')

  const isITAdmin = roles.includes('IT_ADMIN')

useEffect(() => {
  if (!authenticated || !isITAdmin) {
    setUsersList([])
    return
  }

  let cancelled = false

  const fetchUsers = async () => {
    setUsersLoading(true)
    setUsersError(null)

    try {
      await keycloak.updateToken(30)

      const response = await fetch(
        'http://localhost:8000/api/admin/users',
        {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${keycloak.token}`,
          },
        }
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || 'Unable to retrieve users')
      }

      if (!cancelled) {
        setUsersList(data)
      }
    } catch (error) {
      if (!cancelled) {
        setUsersError(error.message)
      }
    } finally {
      if (!cancelled) {
        setUsersLoading(false)
      }
    }
  }

  fetchUsers()

  return () => {
    cancelled = true
  }
}, [authenticated, isITAdmin])

  const fetchAuditEvents = async () => {
    if (!authenticated || !canViewAuditEvents) {
      setAuditEvents([])
      return
    }

    setAuditLoading(true)
    setAuditError(null)

    try {
      await keycloak.updateToken(30)

      const response = await fetch(
        'http://localhost:8000/api/security/events?limit=50&offset=0',
        {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${keycloak.token}`,
          },
        }
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          typeof data.detail === 'string'
            ? data.detail
            : 'Unable to retrieve audit events'
        )
      }

      // Support either a plain array or a paginated response object.
      const events = Array.isArray(data)
        ? data
        : Array.isArray(data.items)
          ? data.items
          : Array.isArray(data.events)
            ? data.events
            : null

      if (!events) {
        throw new Error('The audit API returned an unexpected response format.')
      }

      setAuditEvents(events)
    } catch (error) {
      setAuditError(error.message)
    } finally {
      setAuditLoading(false)
    }
  }

  useEffect(() => {
    if (authenticated && canViewAuditEvents) {
      fetchAuditEvents()
    } else {
      setAuditEvents([])
      setAuditError(null)
    }
  }, [authenticated, canViewAuditEvents])

  const fetchSecurityPolicies = async () => {
    if (!authenticated || !canViewAuditEvents) {
      setSecurityPolicies([])
      return
    }

    setPoliciesLoading(true)
    setPoliciesError(null)

    try {
      await keycloak.updateToken(30)
      const response = await fetch('http://localhost:8000/api/security/policies', {
        method: 'GET',
        headers: { Authorization: `Bearer ${keycloak.token}` },
      })
      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          typeof data.detail === 'string' ? data.detail : 'Unable to retrieve security policies.'
        )
      }

      if (!Array.isArray(data)) {
        throw new Error('The policies API returned an unexpected response format.')
      }

      setSecurityPolicies(data)
    } catch (error) {
      setPoliciesError(error.message)
    } finally {
      setPoliciesLoading(false)
    }
  }

  useEffect(() => {
    if (authenticated && canViewAuditEvents) {
      fetchSecurityPolicies()
    } else {
      setSecurityPolicies([])
      setPoliciesError(null)
    }
  }, [authenticated, canViewAuditEvents])


  const fetchRiskAssessments = async () => {
    if (!authenticated || !canViewAuditEvents) {
      setRiskAssessments([])
      return
    }

    setRisksLoading(true)
    setRisksError(null)

    try {
      await keycloak.updateToken(30)
      const response = await fetch('http://localhost:8000/api/security/risks', {
        method: 'GET',
        headers: { Authorization: `Bearer ${keycloak.token}` },
      })
      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          typeof data.detail === 'string'
            ? data.detail
            : 'Unable to retrieve risk assessments.'
        )
      }
      if (!Array.isArray(data)) {
        throw new Error('The risk assessment API returned an unexpected response format.')
      }
      setRiskAssessments(data)
    } catch (error) {
      setRisksError(error.message)
    } finally {
      setRisksLoading(false)
    }
  }

  useEffect(() => {
    if (authenticated && canViewAuditEvents) {
      fetchRiskAssessments()
    } else {
      setRiskAssessments([])
      setRisksError(null)
    }
  }, [authenticated, canViewAuditEvents])

  const resetRiskForm = (clearMessage = true) => {
    setEditingRiskId(null)
    setRiskForm({
      title: '',
      description: '',
      asset: '',
      category: 'CLOUD_INFRASTRUCTURE',
      likelihood: 3,
      impact: 3,
      status: 'OPEN',
      mitigation_plan: '',
      owner: '',
    })
    if (clearMessage) setRiskMessage(null)
  }

  const handleRiskSubmit = async (event) => {
    event.preventDefault()
    setSavingRisk(true)
    setRiskMessage(null)

    try {
      await keycloak.updateToken(30)
      const isEditing = editingRiskId !== null
      const payload = {
        ...riskForm,
        likelihood: Number(riskForm.likelihood),
        impact: Number(riskForm.impact),
        mitigation_plan: riskForm.mitigation_plan.trim() || null,
        owner: riskForm.owner.trim() || null,
      }
      const response = await fetch(
        isEditing
          ? `http://localhost:8000/api/security/risks/${editingRiskId}`
          : 'http://localhost:8000/api/security/risks',
        {
          method: isEditing ? 'PUT' : 'POST',
          headers: {
            Authorization: `Bearer ${keycloak.token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
        }
      )
      const result = await response.json()

      if (!response.ok) {
        throw new Error(
          typeof result.detail === 'string'
            ? result.detail
            : 'Unable to save the risk assessment.'
        )
      }

      setRiskMessage({
        type: 'success',
        text: `Risk assessment ${isEditing ? 'updated' : 'created'} successfully.`,
      })
      resetRiskForm(false)
      await fetchRiskAssessments()
      await fetchAuditEvents()
    } catch (error) {
      setRiskMessage({ type: 'error', text: error.message })
    } finally {
      setSavingRisk(false)
    }
  }

  const startEditingRisk = (risk) => {
    setEditingRiskId(risk.id)
    setRiskForm({
      title: risk.title,
      description: risk.description,
      asset: risk.asset,
      category: risk.category,
      likelihood: risk.likelihood,
      impact: risk.impact,
      status: risk.status,
      mitigation_plan: risk.mitigation_plan || '',
      owner: risk.owner || '',
    })
    setRiskMessage(null)
  }

  const deleteRiskAssessment = async (risk) => {
    const confirmed = window.confirm(
      `Delete risk assessment "${risk.title}"? This action cannot be undone.`
    )
    if (!confirmed) return

    setRiskMessage(null)
    try {
      await keycloak.updateToken(30)
      const response = await fetch(
        `http://localhost:8000/api/security/risks/${risk.id}`,
        {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${keycloak.token}` },
        }
      )
      const result = await response.json()

      if (!response.ok) {
        throw new Error(
          typeof result.detail === 'string'
            ? result.detail
            : 'Unable to delete the risk assessment.'
        )
      }

      if (editingRiskId === risk.id) resetRiskForm(false)
      setRiskMessage({ type: 'success', text: 'Risk assessment deleted successfully.' })
      await fetchRiskAssessments()
      await fetchAuditEvents()
    } catch (error) {
      setRiskMessage({ type: 'error', text: error.message })
    }
  }

  const resetPolicyForm = () => {
    setEditingPolicyId(null)
    setPolicyForm({
      name: '',
      description: '',
      category: 'IAM',
      severity: 'MEDIUM',
      is_enabled: true,
    })
  }

  const handlePolicySubmit = async (event) => {
    event.preventDefault()
    setSavingPolicy(true)
    setPolicyMessage(null)

    try {
      await keycloak.updateToken(30)
      const isEditing = editingPolicyId !== null
      const response = await fetch(
        isEditing
          ? `http://localhost:8000/api/security/policies/${editingPolicyId}`
          : 'http://localhost:8000/api/security/policies',
        {
          method: isEditing ? 'PUT' : 'POST',
          headers: {
            Authorization: `Bearer ${keycloak.token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(policyForm),
        }
      )
      const result = await response.json()

      if (!response.ok) {
        throw new Error(
          typeof result.detail === 'string'
            ? result.detail
            : 'Unable to save the security policy.'
        )
      }

      setPolicyMessage({
        type: 'success',
        text: `Policy ${isEditing ? 'updated' : 'created'} successfully.`,
      })
      resetPolicyForm()
      await fetchSecurityPolicies()
      await fetchAuditEvents()
    } catch (error) {
      setPolicyMessage({ type: 'error', text: error.message })
    } finally {
      setSavingPolicy(false)
    }
  }

  const startEditingPolicy = (policy) => {
    setEditingPolicyId(policy.id)
    setPolicyForm({
      name: policy.name,
      description: policy.description,
      category: policy.category,
      severity: policy.severity,
      is_enabled: policy.is_enabled,
    })
    setPolicyMessage(null)
  }

  const deleteSecurityPolicy = async (policy) => {
    const confirmed = window.confirm(
      `Delete "${policy.name}"? This action cannot be undone.`
    )
    if (!confirmed) return

    setPolicyMessage(null)
    try {
      await keycloak.updateToken(30)
      const response = await fetch(
        `http://localhost:8000/api/security/policies/${policy.id}`,
        {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${keycloak.token}` },
        }
      )
      const result = response.status === 204 ? null : await response.json()

      if (!response.ok) {
        throw new Error(
          typeof result?.detail === 'string'
            ? result.detail
            : 'Unable to delete the security policy.'
        )
      }

      setPolicyMessage({ type: 'success', text: 'Policy deleted successfully.' })
      if (editingPolicyId === policy.id) resetPolicyForm()
      await fetchSecurityPolicies()
      await fetchAuditEvents()
    } catch (error) {
      setPolicyMessage({ type: 'error', text: error.message })
    }
  }

  // Test authentication with FastAPI
  const testBackendAuthentication = async () => {
    setApiLoading(true)
    setApiResult(null)

    try {
      if (!keycloak.authenticated) {
        throw new Error('Please sign in first.')
      }

      await keycloak.updateToken(30)

      const response = await fetch(
        'http://localhost:8000/api/me',
        {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${keycloak.token}`,
          },
        }
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          data.detail || 'Authentication failed'
        )
      }

      setApiResult({
        success: true,
        data,
      })

    } catch (error) {
      setApiResult({
        success: false,
        message: error.message,
      })

    } finally {
      setApiLoading(false)
    }
  }


  
  // Test all four backend RBAC endpoints
  const testBackendRBAC = async () => {
    setRbacLoading(true)
    setRbacResults([])

    try {
      if (!keycloak.authenticated) {
        throw new Error('Please sign in first.')
      }

      // Refresh token if it is close to expiring
      await keycloak.updateToken(30)

      const token = keycloak.token

      // Test each protected endpoint
      const results = await Promise.all(
        RBAC_ENDPOINTS.map(async (endpoint) => {
          try {
            const response = await fetch(
              `http://localhost:8000${endpoint.path}`,
              {
                method: 'GET',
                headers: {
                  Authorization: `Bearer ${token}`,
                },
              }
            )

            const data = await response.json()

            return {
              name: endpoint.name,
              path: endpoint.path,
              status: response.status,
              success: response.ok,
              message: Array.isArray(data)
                ? `Retrieved ${data.length} users from the database`
                : data.message || data.detail || 'No response message',
              data,
            }

          } catch (error) {
            return {
              name: endpoint.name,
              path: endpoint.path,
              status: 'ERROR',
              success: false,
              message: error.message,
            }
          }
        })
      )

      setRbacResults(results)

    } catch (error) {
      setRbacResults([
        {
          name: 'RBAC test',
          path: '',
          status: 'ERROR',
          success: false,
          message: error.message,
        },
      ])

    } finally {
      setRbacLoading(false)
    }
  }

  // Retrieve an individual user from the backend
const lookupUser = async () => {
  setUserLookupLoading(true)
  setUserLookupResult(null)

  try {
    if (!keycloak.authenticated) {
      throw new Error('Please sign in first.')
    }

    const id = Number(userLookupId)

    if (!Number.isInteger(id) || id < 1) {
      throw new Error('Please enter a valid positive user ID.')
    }

    await keycloak.updateToken(30)

    const response = await fetch(
      `http://localhost:8000/api/admin/users/${id}`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${keycloak.token}`,
        },
      }
    )

    const data = await response.json()

    setUserLookupResult({
      status: response.status,
      success: response.ok,
      data,
    })

  } catch (error) {
    setUserLookupResult({
      status: 'ERROR',
      success: false,
      data: { detail: error.message },
    })

  } finally {
    setUserLookupLoading(false)
  }
}

const handleUpdateUser = async (event) => {
  event.preventDefault()

  if (!editingUser) return

  setUpdatingUser(true)
  setUpdateUserMessage(null)

  try {
    await keycloak.updateToken(30)

    const response = await fetch(
      `http://localhost:8000/api/admin/users/${editingUser.id}`,
      {
        method: 'PUT',
        headers: {
          Authorization: `Bearer ${keycloak.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          first_name: editingUser.first_name,
          last_name: editingUser.last_name,
          email: editingUser.email,
          department_id: Number(editingUser.department_id),
          is_active: editingUser.is_active,
        }),
      }
    )

    const result = await response.json()

    if (!response.ok) {
      throw new Error(
        typeof result.detail === 'string'
          ? result.detail
          : 'Unable to update employee.'
      )
    }

    setUpdateUserMessage({
      type: 'success',
      text: `Employee ${result.username} updated successfully.`,
    })

    // Refresh employee directory.
    const usersResponse = await fetch(
      'http://localhost:8000/api/admin/users',
      {
        headers: {
          Authorization: `Bearer ${keycloak.token}`,
        },
      }
    )

    if (usersResponse.ok) {
      setUsersList(await usersResponse.json())
    }

    // Refresh audit events.
    await fetchAuditEvents()

    setEditingUser(null)

  } catch (error) {
    setUpdateUserMessage({
      type: 'error',
      text: error.message,
    })
  } finally {
    setUpdatingUser(false)
  }
}

const handleCreateUser = async (event) => {
  event.preventDefault()
  setCreatingUser(true)
  setCreateUserMessage(null)

  try {
    await keycloak.updateToken(30)

    const response = await fetch(
      'http://localhost:8000/api/admin/users',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${keycloak.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...newUser,
          department_id: Number(newUser.department_id),
        }),
      }
    )

    const result = await response.json()

    if (!response.ok) {
      throw new Error(
        typeof result.detail === 'string'
          ? result.detail
          : 'Unable to create employee. Check the submitted details.'
      )
    }

    setCreateUserMessage({
      type: 'success',
      text: `Employee ${result.username} created successfully.`,
    })

    setNewUser({
      username: '',
      email: '',
      first_name: '',
      last_name: '',
      department_id: '1',
      temporary_password: '',
    })

    // Refresh the directory with the new database record.
    const usersResponse = await fetch(
      'http://localhost:8000/api/admin/users',
      {
        headers: {
          Authorization: `Bearer ${keycloak.token}`,
        },
      }
    )

    if (usersResponse.ok) {
      setUsersList(await usersResponse.json())
    }

  } catch (error) {
    setCreateUserMessage({
      type: 'error',
      text: error.message,
    })
  } finally {
    setCreatingUser(false)
  }
}


  return (
    <div className="app-shell">

      {/* Sidebar */}
      <aside className="sidebar">

        <p className="nav-label">MAIN MENU</p>

        {canAccess('overview', roles) && (
          <a href="#overview" className="nav-item active">
            ▦ Overview
          </a>
        )}

        {canAccess('users', roles) && (
          <a href="#users" className="nav-item">
            ♙ Identity & Users
          </a>
        )}

        {canAccess('roles', roles) && (
          <a href="#roles" className="nav-item">
            ◈ Roles & Permissions
          </a>
        )}

        {canAccess('policies', roles) && (
          <a href="#policies" className="nav-item">
            ▤ Security Policies
          </a>
        )}

        <p className="nav-label">SECURITY</p>

        {canAccess('events', roles) && (
          <a href="#events" className="nav-item">
            ◉ Audit Events
          </a>
        )}

        {canAccess('risk', roles) && (
          <a href="#risk" className="nav-item">
            ◇ Risk Assessment
          </a>
        )}

        {canAccess('settings', roles) && (
          <a href="#settings" className="nav-item">
            ⚙ Settings
          </a>
        )}

      </aside>

      {/* Main Content */}
      <main className="main-content">

        {/* Top Navigation */}
        <header className="topbar">

          <div>
            <h1 className="page-title">
              Security Overview
            </h1>

            <p className="page-subtitle">
              Welcome to your CloudGuard security workspace.
            </p>
          </div>

          {authenticated ? (

            <div className="auth-panel">

              <span className="status">
                ● Authenticated
              </span>

              <span className="username">
                {user?.preferred_username}
              </span>

              <button
                className="auth-button"
                onClick={logout}
              >
                Logout
              </button>

            </div>

          ) : (

            <button
              className="auth-button"
              onClick={login}
            >
              Sign in with CloudGuard
            </button>

          )}

        </header>

        {/* User Identity */}
        {authenticated && (

          <section className="panel">

            <h2 className="panel-title">
              Your Identity
            </h2>

            <p className="stat-label">
              Username: {user?.preferred_username}
            </p>

            <p className="stat-label">
              Email: {user?.email || 'Not available'}
            </p>

            <p className="stat-label">
              Assigned CloudGuard roles:
              {' '}
              {roles.length > 0
                ? roles.join(', ')
                : 'No application roles assigned'}
            </p>

          </section>

        )}

        {/* Backend Authentication Test */}
        <section className="panel">

          <h2 className="panel-title">
            Backend Authentication Test
          </h2>

          <p className="stat-label">
            Verify your Keycloak identity directly with the
            CloudGuard backend.
          </p>

          <button
            className="auth-button"
            onClick={testBackendAuthentication}
            disabled={apiLoading || !authenticated}
          >
            {apiLoading
              ? 'Verifying...'
              : 'Test Backend Authentication'}
          </button>

          {apiResult && (

            <div style={{ marginTop: '20px' }}>

              {apiResult.success ? (

                <>
                  <p style={{ color: '#22c55e' }}>
                    ✓ Backend authentication successful
                  </p>

                  <pre style={{ whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(apiResult.data, null, 2)}
                  </pre>
                </>

              ) : (

                <p style={{ color: '#ef4444' }}>
                  ✕ {apiResult.message}
                </p>

              )}

            </div>

          )}

        </section>

        {/* Backend RBAC Test */}
        <section className="panel">

          <h2 className="panel-title">
            Backend Role-Based Access Control
          </h2>

          <p className="stat-label">
            Test whether the backend permits or denies access
            according to your Keycloak application roles.
          </p>

          <button
            className="auth-button"
            onClick={testBackendRBAC}
            disabled={rbacLoading || !authenticated}
          >
            {rbacLoading
              ? 'Testing permissions...'
              : 'Test All RBAC Endpoints'}
          </button>

          {rbacResults.length > 0 && (

            <div style={{ marginTop: '20px' }}>

              {rbacResults.map((result) => (

                <div
                  key={result.path || result.name}
                  style={{
                    padding: '12px',
                    marginBottom: '10px',
                    borderRadius: '8px',
                    background: 'rgba(255,255,255,0.04)',
                  }}
                >

                  <p style={{ fontWeight: 'bold' }}>
                    {result.name}
                  </p>

                  <p className="stat-label">
                    {result.path}
                  </p>

                  <p
                    style={{
                      color:
                        result.status === 200
                          ? '#22c55e'
                          : result.status === 403
                            ? '#f59e0b'
                            : '#ef4444',
                    }}
                  >
                    HTTP {result.status}
                    {' — '}
                    {result.status === 200
                      ? 'Access granted'
                      : result.status === 403
                        ? 'Access denied'
                        : 'Unexpected response'}
                  </p>

                  <p className="stat-label">
                    {result.message}
                  </p>

                  {result.path === '/api/admin/users' &&
                    Array.isArray(result.data) &&
                    result.data.length > 0 && (
                      <div style={{ marginTop: '16px', overflowX: 'auto' }}>
                        <h3 style={{ marginBottom: '12px' }}>
                          CloudGuard Users
                        </h3>

                        <table
                          style={{
                            width: '100%',
                            borderCollapse: 'collapse',
                            textAlign: 'left',
                          }}
                        >
                          <thead>
                            <tr>
                              {['Name', 'Username', 'Email', 'Department', 'Status'].map(
                                (heading) => (
                                  <th
                                    key={heading}
                                    style={{
                                      padding: '10px 8px',
                                      borderBottom: '1px solid rgba(255,255,255,0.15)',
                                      fontSize: '13px',
                                    }}
                                  >
                                    {heading}
                                  </th>
                                ),
                              )}
                            </tr>
                          </thead>

                          <tbody>
                            {result.data.map((cloudUser) => (
                              <tr key={cloudUser.id}>
                                <td style={{ padding: '10px 8px' }}>
                                  {cloudUser.full_name || '—'}
                                </td>
                                <td style={{ padding: '10px 8px' }}>
                                  {cloudUser.username}
                                </td>
                                <td style={{ padding: '10px 8px' }}>
                                  {cloudUser.email || '—'}
                                </td>
                                <td style={{ padding: '10px 8px' }}>
                                  {cloudUser.department?.name || 'Unassigned'}
                                </td>
                                <td style={{ padding: '10px 8px' }}>
                                  <span
                                    style={{
                                      color: cloudUser.is_active ? '#22c55e' : '#ef4444',
                                    }}
                                  >
                                    {cloudUser.is_active ? 'Active' : 'Inactive'}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}

                </div>

              ))}

            </div>

          )}

        </section>


        {/* Individual User Lookup — IT administrators only */}
        {authenticated && isITAdmin && (
        <section className="panel">
          <h2 className="panel-title">
            Individual User Lookup
          </h2>

          <p className="stat-label">
            Retrieve an individual user profile from the CloudGuard database.
          </p>

          <div style={{
            display: 'flex',
            gap: '12px',
            alignItems: 'center',
            flexWrap: 'wrap',
            marginTop: '16px',
          }}>
            <input
              type="number"
              min="1"
              value={userLookupId}
              onChange={(e) => setUserLookupId(e.target.value)}
              placeholder="Enter user ID"
              style={{
                padding: '12px',
                borderRadius: '8px',
                border: '1px solid #334155',
                background: '#0f172a',
                color: '#ffffff',
                width: '180px',
              }}
            />

            <button
              className="auth-button"
              onClick={lookupUser}
              disabled={userLookupLoading || !authenticated}
            >
              {userLookupLoading ? 'Looking up...' : 'Find User'}
            </button>
          </div>

          {userLookupResult && (
            <div style={{ marginTop: '20px' }}>
              <p style={{
                color: userLookupResult.success ? '#22c55e' : '#ef4444',
              }}>
                HTTP {userLookupResult.status}
                {' — '}
                {userLookupResult.success ? 'User retrieved' : 'Request failed'}
              </p>

              <pre style={{
                whiteSpace: 'pre-wrap',
                overflowX: 'auto',
                padding: '16px',
                borderRadius: '8px',
                background: 'rgba(0,0,0,0.2)',
              }}>
                {JSON.stringify(userLookupResult.data, null, 2)}
              </pre>
            </div>
          )}
        </section>
        )}

{/* Edit Employee Form */}
{authenticated && isITAdmin && editingUser && (
  <section className="panel" id="edit-employee">
    <h2 className="panel-title">Edit Employee</h2>

    <p className="stat-label">
      Updating employee ID: {editingUser.id}
    </p>

    <form className="user-form" onSubmit={handleUpdateUser}>
      <div className="form-grid">
        <div className="form-field">
          <label htmlFor="edit-first-name">First Name</label>
          <input
            id="edit-first-name"
            className="form-input"
            required
            maxLength={75}
            value={editingUser.first_name}
            onChange={(e) =>
              setEditingUser({
                ...editingUser,
                first_name: e.target.value,
              })
            }
          />
        </div>

        <div className="form-field">
          <label htmlFor="edit-last-name">Last Name</label>
          <input
            id="edit-last-name"
            className="form-input"
            required
            maxLength={75}
            value={editingUser.last_name}
            onChange={(e) =>
              setEditingUser({
                ...editingUser,
                last_name: e.target.value,
              })
            }
          />
        </div>

        <div className="form-field">
          <label htmlFor="edit-email">Email</label>
          <input
            id="edit-email"
            type="email"
            className="form-input"
            required
            maxLength={255}
            value={editingUser.email}
            onChange={(e) =>
              setEditingUser({
                ...editingUser,
                email: e.target.value,
              })
            }
          />
        </div>

        <div className="form-field">
          <label htmlFor="edit-department">Department</label>
          <select
            id="edit-department"
            className="form-select"
            value={editingUser.department_id}
            onChange={(e) =>
              setEditingUser({
                ...editingUser,
                department_id: e.target.value,
              })
            }
          >
            <option value="1">IT</option>
            <option value="2">SECURITY</option>
            <option value="3">HR</option>
            <option value="4">FINANCE</option>
          </select>
        </div>

        <div className="form-field">
          <label htmlFor="edit-status">Account Status</label>
          <select
            id="edit-status"
            className="form-select"
            value={String(editingUser.is_active)}
            onChange={(e) =>
              setEditingUser({
                ...editingUser,
                is_active: e.target.value === 'true',
              })
            }
          >
            <option value="true">Active</option>
            <option value="false">Inactive</option>
          </select>
        </div>
      </div>

      <div className="form-actions">
        <button
          type="submit"
          className="auth-button"
          disabled={updatingUser}
        >
          {updatingUser ? 'Saving Changes...' : 'Save Changes'}
        </button>

        <button
          type="button"
          className="auth-button"
          disabled={updatingUser}
          onClick={() => {
            setEditingUser(null)
            setUpdateUserMessage(null)
          }}
        >
          Cancel
        </button>
      </div>

      {updateUserMessage && (
        <div className={`form-message ${updateUserMessage.type}`}>
          {updateUserMessage.text}
        </div>
      )}
    </form>
  </section>
)}

{/* Identity & Users Directory */}
{authenticated && isITAdmin && (
  <section className="panel" id="users">
    <h2 className="panel-title">
      Identity & Users
    </h2>

    <p className="stat-label">
      Manage employee identities registered in CloudGuard.
    </p>

    {usersLoading && (
      <p className="stat-label">Loading users...</p>
    )}

    {usersError && (
      <p style={{ color: '#ef4444' }}>
        {usersError}
      </p>
    )}

    {!usersLoading && !usersError && (
      <>
        <p className="stat-label">
          Total registered users: {usersList.length}
        </p>

        <div style={{ overflowX: 'auto', marginTop: '16px' }}>
          <table
            style={{
              width: '100%',
              borderCollapse: 'collapse',
              textAlign: 'left',
            }}
          >
            <thead>
              <tr>
                {[
                  'ID',
                  'Full Name',
                  'Username',
                  'Email',
                  'Department',
                  'Status',
                  'Actions',
                ].map((heading) => (
                  <th
                    key={heading}
                    style={{
                      padding: '12px 10px',
                      borderBottom: '1px solid rgba(255,255,255,0.15)',
                      fontSize: '13px',
                    }}
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>

            <tbody>
              {usersList.map((cloudUser) => (
                <tr key={cloudUser.id}>
                  <td style={{ padding: '12px 10px' }}>
                    {cloudUser.id}
                  </td>
                  <td style={{ padding: '12px 10px' }}>
                    {cloudUser.full_name || '—'}
                  </td>
                  <td style={{ padding: '12px 10px' }}>
                    {cloudUser.username}
                  </td>
                  <td style={{ padding: '12px 10px' }}>
                    {cloudUser.email || '—'}
                  </td>
                  <td style={{ padding: '12px 10px' }}>
                    {cloudUser.department?.name || 'Unassigned'}
                  </td>
                  <td style={{ padding: '12px 10px' }}>
                    <span style={{
                      color: cloudUser.is_active ? '#22c55e' : '#ef4444',
                    }}>
                      {cloudUser.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td style={{ padding: '12px 10px' }}>
                    <button
                      className="auth-button"
                      onClick={() => {
                        setEditingUser({
                          id: cloudUser.id,
                          first_name: cloudUser.full_name?.split(' ')[0] || '',
                          last_name: cloudUser.full_name?.split(' ').slice(1).join(' ') || '',
                          email: cloudUser.email || '',
                          department_id: String(cloudUser.department?.id || 1),
                          is_active: cloudUser.is_active,
                        })
                        setUpdateUserMessage(null)
                      }}
                    >
                      Edit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </>
    )}
  </section>
)}



{/* Create Employee Form */}
{authenticated && isITAdmin && (
  <section className="panel" id="create-employee">
    <h2 className="panel-title">Create New Employee</h2>

    <p className="stat-label">
      Register a new employee in CloudGuard Identity Management.
    </p>

    <form className="user-form" onSubmit={handleCreateUser}>
      <div className="form-grid">
        <div className="form-field">
          <label htmlFor="first_name">First Name</label>
          <input
            id="first_name"
            className="form-input"
            required
            maxLength={75}
            value={newUser.first_name}
            onChange={(e) =>
              setNewUser({ ...newUser, first_name: e.target.value })
            }
            placeholder="Enter first name"
          />
        </div>

        <div className="form-field">
          <label htmlFor="last_name">Last Name</label>
          <input
            id="last_name"
            className="form-input"
            required
            maxLength={75}
            value={newUser.last_name}
            onChange={(e) =>
              setNewUser({ ...newUser, last_name: e.target.value })
            }
            placeholder="Enter last name"
          />
        </div>

        <div className="form-field">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            className="form-input"
            required
            minLength={3}
            maxLength={100}
            value={newUser.username}
            onChange={(e) =>
              setNewUser({ ...newUser, username: e.target.value })
            }
            placeholder="e.g. john.smith"
          />
        </div>

        <div className="form-field">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            className="form-input"
            required
            maxLength={255}
            value={newUser.email}
            onChange={(e) =>
              setNewUser({ ...newUser, email: e.target.value })
            }
            placeholder="employee@example.com"
          />
        </div>

        <div className="form-field">
          <label htmlFor="department">Department</label>
          <select
            id="department"
            className="form-select"
            value={newUser.department_id}
            onChange={(e) =>
              setNewUser({ ...newUser, department_id: e.target.value })
            }
          >
            <option value="1">IT</option>
            <option value="2">SECURITY</option>
            <option value="3">HR</option>
            <option value="4">FINANCE</option>
          </select>
        </div>

        <div className="form-field">
          <label htmlFor="temporary_password">Temporary Password</label>
          <input
            id="temporary_password"
            type="password"
            className="form-input"
            required
            minLength={12}
            maxLength={128}
            autoComplete="new-password"
            value={newUser.temporary_password}
            onChange={(e) =>
              setNewUser({
                ...newUser,
                temporary_password: e.target.value,
              })
            }
            placeholder="Minimum 12 characters"
          />
          <span className="form-help">
            Employee will be required to change this password at first login.
          </span>
        </div>
      </div>

      <div className="form-actions">
        <button
          type="submit"
          className="auth-button"
          disabled={creatingUser}
        >
          {creatingUser ? 'Creating Employee...' : 'Create Employee'}
        </button>
      </div>

      {createUserMessage && (
        <div className={`form-message ${createUserMessage.type}`}>
          {createUserMessage.text}
        </div>
      )}
    </form>
  </section>
)}



        {/* Roles & Permissions — role catalogue and route-level access matrix */}
        {authenticated && canAccess('roles', roles) && (
          <section className="panel" id="roles">
            <div className="section-heading">
              <div>
                <h2 className="panel-title">Roles &amp; Permissions</h2>
                <p className="stat-label">
                  Review CloudGuard application roles and the protected areas each role can access.
                </p>
              </div>
              <span className="role-count">4 configured roles</span>
            </div>

            <div className="role-summary-grid">
              <article className="role-card">
                <span className="role-tag admin">ADMINISTRATOR</span>
                <h3>IT Admin</h3>
                <p>Manages user identities and has access to security administration and audit activity.</p>
                <div className="role-card-meta">Realm role: <strong>IT_ADMIN</strong></div>
              </article>
              <article className="role-card">
                <span className="role-tag security">SECURITY</span>
                <h3>Security Analyst</h3>
                <p>Reviews security operations, security policies, and audit events.</p>
                <div className="role-card-meta">Realm role: <strong>SECURITY_ANALYST</strong></div>
              </article>
              <article className="role-card">
                <span className="role-tag hr">HUMAN RESOURCES</span>
                <h3>HR Manager</h3>
                <p>Accesses the HR dashboard through its role-protected API endpoint.</p>
                <div className="role-card-meta">Realm role: <strong>HR_MANAGER</strong></div>
              </article>
              <article className="role-card">
                <span className="role-tag finance">FINANCE</span>
                <h3>Finance Analyst</h3>
                <p>Accesses the finance dashboard through its role-protected API endpoint.</p>
                <div className="role-card-meta">Realm role: <strong>FINANCE_ANALYST</strong></div>
              </article>
            </div>

            <div className="role-section-block">
              <h3 className="policy-form-title">Protected API Access Matrix</h3>
              <p className="stat-label">
                These permissions reflect the role requirements configured on the CloudGuard backend routes.
              </p>
              <div className="policy-table-wrap">
                <table className="policy-table role-permissions-table">
                  <thead>
                    <tr>
                      <th>Protected Area</th>
                      <th>API Endpoint</th>
                      <th>Authorized Roles</th>
                      <th>Your Access</th>
                    </tr>
                  </thead>
                  <tbody>
                    {RBAC_ENDPOINTS.map((endpoint) => {
                      const hasAccess = endpoint.roles.some((role) => roles.includes(role))
                      return (
                        <tr key={endpoint.path}>
                          <td><strong>{endpoint.name}</strong></td>
                          <td><code className="role-endpoint">{endpoint.path}</code></td>
                          <td>
                            <div className="role-chip-list">
                              {endpoint.roles.map((role) => (
                                <span className="role-chip" key={role}>{role}</span>
                              ))}
                            </div>
                          </td>
                          <td>
                            <span className={`policy-status ${hasAccess ? 'enabled' : 'disabled'}`}>
                              {hasAccess ? 'Granted' : 'Not granted'}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="role-session-panel">
              <div>
                <h3 className="policy-form-title">Current Session</h3>
                <p className="stat-label">Roles currently present in your authenticated Keycloak session.</p>
                <div className="role-chip-list session-role-list">
                  {roles.length > 0
                    ? roles.map((role) => <span className="role-chip current" key={role}>{role}</span>)
                    : <span className="stat-label">No CloudGuard application roles assigned.</span>}
                </div>
              </div>
              <div className="role-session-user">
                <span className="stat-label">Signed in as</span>
                <strong>{user?.preferred_username || 'Unknown user'}</strong>
              </div>
            </div>

            <p className="role-footnote">
              Role membership is managed by the Keycloak identity provider. This page is a visibility and access-review screen; it does not modify realm roles or user assignments.
            </p>
          </section>
        )}

        {/* Security Policies — IT administrators and security analysts */}
        {authenticated && canViewAuditEvents && (
          <section className="panel" id="policies">
            <div className="section-heading">
              <div>
                <h2 className="panel-title">Security Policies</h2>
                <p className="stat-label">
                  Create and manage security controls stored in the CloudGuard database.
                </p>
              </div>
              <button
                type="button"
                className="auth-button secondary-button"
                onClick={fetchSecurityPolicies}
                disabled={policiesLoading}
              >
                {policiesLoading ? 'Refreshing...' : 'Refresh Policies'}
              </button>
            </div>

            <form className="user-form" onSubmit={handlePolicySubmit}>
              <h3 className="policy-form-title">
                {editingPolicyId === null ? 'Create Policy' : `Edit Policy #${editingPolicyId}`}
              </h3>

              <div className="form-grid">
                <div className="form-field">
                  <label htmlFor="policy-name">Policy Name</label>
                  <input
                    id="policy-name"
                    className="form-input"
                    required
                    minLength={3}
                    maxLength={120}
                    value={policyForm.name}
                    onChange={(event) =>
                      setPolicyForm({ ...policyForm, name: event.target.value })
                    }
                    placeholder="e.g. Multi-Factor Authentication Policy"
                  />
                </div>

                <div className="form-field">
                  <label htmlFor="policy-category">Category</label>
                  <select
                    id="policy-category"
                    className="form-select"
                    value={policyForm.category}
                    onChange={(event) =>
                      setPolicyForm({ ...policyForm, category: event.target.value })
                    }
                  >
                    <option value="IAM">IAM</option>
                    <option value="PASSWORD">Password</option>
                    <option value="ACCESS_CONTROL">Access Control</option>
                    <option value="NETWORK">Network</option>
                    <option value="DATA_PROTECTION">Data Protection</option>
                  </select>
                </div>

                <div className="form-field">
                  <label htmlFor="policy-severity">Severity</label>
                  <select
                    id="policy-severity"
                    className="form-select"
                    value={policyForm.severity}
                    onChange={(event) =>
                      setPolicyForm({ ...policyForm, severity: event.target.value })
                    }
                  >
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                    <option value="CRITICAL">Critical</option>
                  </select>
                </div>

                <div className="form-field policy-enabled-field">
                  <label htmlFor="policy-enabled">Policy Status</label>
                  <label className="policy-toggle">
                    <input
                      id="policy-enabled"
                      type="checkbox"
                      checked={policyForm.is_enabled}
                      onChange={(event) =>
                        setPolicyForm({ ...policyForm, is_enabled: event.target.checked })
                      }
                    />
                    Enabled
                  </label>
                </div>

                <div className="form-field form-field-wide">
                  <label htmlFor="policy-description">Description</label>
                  <textarea
                    id="policy-description"
                    className="form-input policy-description"
                    required
                    minLength={10}
                    maxLength={2000}
                    rows={3}
                    value={policyForm.description}
                    onChange={(event) =>
                      setPolicyForm({ ...policyForm, description: event.target.value })
                    }
                    placeholder="Describe the security requirement and expected control."
                  />
                </div>
              </div>

              <div className="form-actions">
                <button type="submit" className="auth-button" disabled={savingPolicy}>
                  {savingPolicy
                    ? 'Saving...'
                    : editingPolicyId === null
                      ? 'Create Policy'
                      : 'Save Changes'}
                </button>
                {editingPolicyId !== null && (
                  <button
                    type="button"
                    className="auth-button secondary-button"
                    onClick={resetPolicyForm}
                    disabled={savingPolicy}
                  >
                    Cancel Edit
                  </button>
                )}
              </div>
              {policyMessage && (
                <div className={`form-message ${policyMessage.type}`}>
                  {policyMessage.text}
                </div>
              )}
            </form>

            <div className="policy-list-heading">
              <h3 className="policy-form-title">Configured Policies</h3>
              <span className="policy-count">{securityPolicies.length} total</span>
            </div>

            {policiesLoading && securityPolicies.length === 0 && (
              <p className="stat-label">Loading security policies...</p>
            )}
            {policiesError && (
              <p className="policy-error">{policiesError}</p>
            )}
            {!policiesLoading && !policiesError && securityPolicies.length === 0 && (
              <p className="empty-state">No security policies have been created yet.</p>
            )}

            {securityPolicies.length > 0 && (
              <div className="policy-table-wrap">
                <table className="policy-table">
                  <thead>
                    <tr>
                      <th>Policy</th>
                      <th>Category</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Created By</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {securityPolicies.map((policy) => (
                      <tr key={policy.id}>
                        <td>
                          <strong>{policy.name}</strong>
                          <span className="policy-description-cell">{policy.description}</span>
                        </td>
                        <td>{policy.category.replaceAll('_', ' ')}</td>
                        <td>
                          <span className={`severity-pill severity-${policy.severity.toLowerCase()}`}>
                            {policy.severity}
                          </span>
                        </td>
                        <td>
                          <span className={policy.is_enabled ? 'policy-status enabled' : 'policy-status disabled'}>
                            {policy.is_enabled ? 'Enabled' : 'Disabled'}
                          </span>
                        </td>
                        <td>{policy.created_by}</td>
                        <td>
                          <div className="policy-actions">
                            <button
                              type="button"
                              className="table-action"
                              onClick={() => startEditingPolicy(policy)}
                            >
                              Edit
                            </button>
                            <button
                              type="button"
                              className="table-action danger-action"
                              onClick={() => deleteSecurityPolicy(policy)}
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}


        {/* Risk Assessment — IT administrators and security analysts */}
        {authenticated && canViewAuditEvents && (
          <section className="panel" id="risk">
            <div className="section-heading">
              <div>
                <h2 className="panel-title">Risk Assessment</h2>
                <p className="stat-label">
                  Identify cloud security risks, calculate inherent risk scores, and track mitigation progress.
                </p>
              </div>
              <span className="role-count">{riskAssessments.length} recorded risks</span>
            </div>

            <div className="risk-summary-grid">
              {[
                { label: 'Critical', value: riskAssessments.filter((risk) => risk.severity === 'CRITICAL').length, tone: 'critical' },
                { label: 'High', value: riskAssessments.filter((risk) => risk.severity === 'HIGH').length, tone: 'high' },
                { label: 'Medium', value: riskAssessments.filter((risk) => risk.severity === 'MEDIUM').length, tone: 'medium' },
                { label: 'Low', value: riskAssessments.filter((risk) => risk.severity === 'LOW').length, tone: 'low' },
              ].map((item) => (
                <div className="risk-summary-card" key={item.label}>
                  <span className={`severity-pill severity-${item.tone}`}>{item.label}</span>
                  <strong>{risksLoading ? '—' : item.value}</strong>
                  <span className="form-help">Risk records</span>
                </div>
              ))}
            </div>

            <h3 className="policy-form-title risk-form-heading">
              {editingRiskId === null ? 'Record a New Risk' : `Edit Risk Assessment #${editingRiskId}`}
            </h3>

            <form className="user-form" onSubmit={handleRiskSubmit}>
              <div className="form-grid">
                <div className="form-field">
                  <label htmlFor="risk-title">Risk Title</label>
                  <input
                    id="risk-title"
                    className="form-input"
                    required
                    minLength={3}
                    maxLength={150}
                    value={riskForm.title}
                    onChange={(event) => setRiskForm({ ...riskForm, title: event.target.value })}
                    placeholder="e.g. Unauthorized access to cloud storage"
                  />
                </div>

                <div className="form-field">
                  <label htmlFor="risk-asset">Affected Asset</label>
                  <input
                    id="risk-asset"
                    className="form-input"
                    required
                    minLength={2}
                    maxLength={150}
                    value={riskForm.asset}
                    onChange={(event) => setRiskForm({ ...riskForm, asset: event.target.value })}
                    placeholder="e.g. Production object storage"
                  />
                </div>

                <div className="form-field">
                  <label htmlFor="risk-category">Category</label>
                  <select
                    id="risk-category"
                    className="form-select"
                    value={riskForm.category}
                    onChange={(event) => setRiskForm({ ...riskForm, category: event.target.value })}
                  >
                    <option value="IAM">Identity &amp; Access Management</option>
                    <option value="NETWORK">Network</option>
                    <option value="ENDPOINT">Endpoint</option>
                    <option value="APPLICATION">Application</option>
                    <option value="DATA_PROTECTION">Data Protection</option>
                    <option value="CLOUD_INFRASTRUCTURE">Cloud Infrastructure</option>
                  </select>
                </div>

                <div className="form-field">
                  <label htmlFor="risk-status">Status</label>
                  <select
                    id="risk-status"
                    className="form-select"
                    value={riskForm.status}
                    onChange={(event) => setRiskForm({ ...riskForm, status: event.target.value })}
                  >
                    <option value="OPEN">Open</option>
                    <option value="IN_PROGRESS">In Progress</option>
                    <option value="MITIGATED">Mitigated</option>
                    <option value="ACCEPTED">Accepted</option>
                  </select>
                </div>

                <div className="form-field">
                  <label htmlFor="risk-likelihood">Likelihood (1–5)</label>
                  <select
                    id="risk-likelihood"
                    className="form-select"
                    value={riskForm.likelihood}
                    onChange={(event) => setRiskForm({ ...riskForm, likelihood: Number(event.target.value) })}
                  >
                    {[1, 2, 3, 4, 5].map((value) => (
                      <option key={value} value={value}>{value} — {['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'][value - 1]}</option>
                    ))}
                  </select>
                </div>

                <div className="form-field">
                  <label htmlFor="risk-impact">Impact (1–5)</label>
                  <select
                    id="risk-impact"
                    className="form-select"
                    value={riskForm.impact}
                    onChange={(event) => setRiskForm({ ...riskForm, impact: Number(event.target.value) })}
                  >
                    {[1, 2, 3, 4, 5].map((value) => (
                      <option key={value} value={value}>{value} — {['Insignificant', 'Minor', 'Moderate', 'Major', 'Severe'][value - 1]}</option>
                    ))}
                  </select>
                </div>

                <div className="form-field">
                  <label htmlFor="risk-owner">Risk Owner (optional)</label>
                  <input
                    id="risk-owner"
                    className="form-input"
                    maxLength={100}
                    value={riskForm.owner}
                    onChange={(event) => setRiskForm({ ...riskForm, owner: event.target.value })}
                    placeholder="e.g. Security Team"
                  />
                </div>

                <div className="form-field">
                  <label>Calculated Risk Score</label>
                  <div className="risk-score-preview">
                    <strong>{Number(riskForm.likelihood) * Number(riskForm.impact)} / 25</strong>
                    <span>
                      {(() => {
                        const score = Number(riskForm.likelihood) * Number(riskForm.impact)
                        return score <= 4 ? 'LOW' : score <= 9 ? 'MEDIUM' : score <= 16 ? 'HIGH' : 'CRITICAL'
                      })()}
                    </span>
                  </div>
                </div>

                <div className="form-field form-field-wide">
                  <label htmlFor="risk-description">Risk Description</label>
                  <textarea
                    id="risk-description"
                    className="form-input policy-description"
                    required
                    minLength={10}
                    maxLength={4000}
                    rows={3}
                    value={riskForm.description}
                    onChange={(event) => setRiskForm({ ...riskForm, description: event.target.value })}
                    placeholder="Describe the threat, vulnerability, and potential business impact."
                  />
                </div>

                <div className="form-field form-field-wide">
                  <label htmlFor="risk-mitigation">Mitigation Plan (optional)</label>
                  <textarea
                    id="risk-mitigation"
                    className="form-input policy-description"
                    maxLength={4000}
                    rows={3}
                    value={riskForm.mitigation_plan}
                    onChange={(event) => setRiskForm({ ...riskForm, mitigation_plan: event.target.value })}
                    placeholder="Describe the controls or actions planned to reduce this risk."
                  />
                </div>
              </div>

              <div className="form-actions">
                <button type="submit" className="auth-button" disabled={savingRisk}>
                  {savingRisk ? 'Saving...' : editingRiskId === null ? 'Create Risk Assessment' : 'Save Changes'}
                </button>
                {editingRiskId !== null && (
                  <button
                    type="button"
                    className="auth-button secondary-button"
                    onClick={resetRiskForm}
                    disabled={savingRisk}
                  >
                    Cancel Edit
                  </button>
                )}
                <button
                  type="button"
                  className="auth-button secondary-button"
                  onClick={fetchRiskAssessments}
                  disabled={risksLoading || savingRisk}
                >
                  {risksLoading ? 'Refreshing...' : 'Refresh Risks'}
                </button>
              </div>
              {riskMessage && (
                <div className={`form-message ${riskMessage.type}`}>{riskMessage.text}</div>
              )}
            </form>

            <div className="policy-list-heading">
              <h3 className="policy-form-title">Risk Register</h3>
              <span className="policy-count">{riskAssessments.length} total</span>
            </div>

            {risksLoading && riskAssessments.length === 0 && (
              <p className="stat-label">Loading risk assessments...</p>
            )}
            {risksError && <p className="policy-error">{risksError}</p>}
            {!risksLoading && !risksError && riskAssessments.length === 0 && (
              <p className="empty-state">No risk assessments have been recorded yet.</p>
            )}

            {riskAssessments.length > 0 && (
              <div className="policy-table-wrap">
                <table className="policy-table risk-table">
                  <thead>
                    <tr>
                      <th>Risk</th>
                      <th>Category</th>
                      <th>Score</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Owner</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {riskAssessments.map((risk) => (
                      <tr key={risk.id}>
                        <td>
                          <strong>{risk.title}</strong>
                          <span className="policy-description-cell">
                            Asset: {risk.asset}<br />
                            {risk.description}
                          </span>
                        </td>
                        <td>{risk.category.replaceAll('_', ' ')}</td>
                        <td>
                          <strong className="risk-score-value">{risk.risk_score}/25</strong>
                          <span className="policy-description-cell">
                            L {risk.likelihood} × I {risk.impact}
                          </span>
                        </td>
                        <td>
                          <span className={`severity-pill severity-${risk.severity.toLowerCase()}`}>
                            {risk.severity}
                          </span>
                        </td>
                        <td>
                          <span className={`risk-status risk-status-${risk.status.toLowerCase()}`}>
                            {risk.status.replaceAll('_', ' ')}
                          </span>
                        </td>
                        <td>{risk.owner || 'Unassigned'}</td>
                        <td>
                          <div className="policy-actions">
                            <button type="button" className="table-action" onClick={() => startEditingRisk(risk)}>
                              Edit
                            </button>
                            <button type="button" className="table-action danger-action" onClick={() => deleteRiskAssessment(risk)}>
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="form-help" style={{ marginTop: '12px' }}>
              Risk score = likelihood × impact. Severity is assigned by the backend from the calculated score.
            </p>
          </section>
        )}

        {/* Audit Events — IT administrators and security analysts */}
        {authenticated && canViewAuditEvents && (
          <section className="panel" id="events">
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: '12px',
              flexWrap: 'wrap',
            }}>
              <div>
                <h2 className="panel-title">Audit Events</h2>
                <p className="stat-label">
                  Security-relevant activity recorded by CloudGuard.
                </p>
              </div>

              <button
                className="auth-button"
                onClick={fetchAuditEvents}
                disabled={auditLoading}
              >
                {auditLoading ? 'Refreshing...' : 'Refresh Events'}
              </button>
            </div>

            {auditLoading && auditEvents.length === 0 && (
              <p className="stat-label">Loading audit events...</p>
            )}

            {auditError && (
              <p style={{ color: '#ef4444', marginTop: '16px' }}>
                {auditError}
              </p>
            )}

            {!auditLoading && !auditError && auditEvents.length === 0 && (
              <p className="stat-label" style={{ marginTop: '16px' }}>
                No audit events have been recorded yet.
              </p>
            )}

            {auditEvents.length > 0 && (
              <div style={{ overflowX: 'auto', marginTop: '18px' }}>
                <table style={{
                  width: '100%',
                  borderCollapse: 'collapse',
                  textAlign: 'left',
                }}>
                  <thead>
                    <tr>
                      {['Time', 'Actor', 'Action', 'Resource', 'Outcome', 'Source IP'].map(
                        (heading) => (
                          <th
                            key={heading}
                            style={{
                              padding: '11px 9px',
                              borderBottom: '1px solid rgba(255,255,255,0.15)',
                              fontSize: '13px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {heading}
                          </th>
                        )
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {auditEvents.map((event) => (
                      <tr key={event.id}>
                        <td style={{ padding: '11px 9px', whiteSpace: 'nowrap' }}>
                          {event.created_at
                            ? new Date(event.created_at).toLocaleString()
                            : '—'}
                        </td>
                        <td style={{ padding: '11px 9px' }}>
                          {event.username || 'Unknown'}
                        </td>
                        <td style={{ padding: '11px 9px' }}>
                          {event.action || '—'}
                        </td>
                        <td style={{ padding: '11px 9px' }}>
                          {[event.resource_type, event.resource_id]
                            .filter(Boolean)
                            .join(' / ') || '—'}
                        </td>
                        <td style={{ padding: '11px 9px' }}>
                          <span style={{
                            color: event.outcome === 'SUCCESS' ? '#22c55e' : '#f59e0b',
                            fontWeight: 600,
                          }}>
                            {event.outcome || '—'}
                          </span>
                        </td>
                        <td style={{ padding: '11px 9px' }}>
                          {event.source_ip || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <p className="form-help" style={{ marginTop: '12px' }}>
              Showing up to 50 most recent events.
            </p>
          </section>
        )}

        {/* Dashboard Statistics */}
        <section className="stats-grid">

          {authenticated && isITAdmin && (
            <div className="stat-card">
              <p className="stat-label">Total Users</p>
              <div className="stat-value">
                {usersLoading ? '...' : usersError ? '—' : usersList.length.toString().padStart(2, '0')}
              </div>
              <p className="stat-description">
                Registered identities
              </p>
            </div>
          )}

          <div className="stat-card">
            <p className="stat-label">Access Roles</p>
            <div className="stat-value">04</div>
            <p className="stat-description">
              Custom realm roles
            </p>
          </div>

          <div className="stat-card">
            <p className="stat-label">Departments</p>
            <div className="stat-value">04</div>
            <p className="stat-description">
              Configured user groups
            </p>
          </div>

          <div className="stat-card">
            <p className="stat-label">Identity Provider</p>
            <div className="stat-value">Online</div>
            <p className="stat-description">
              Keycloak identity service
            </p>
          </div>

        </section>

        {/* Identity Management */}
        <section className="panel">

          <h2 className="panel-title">
            Identity & Access Management
          </h2>

          <p className="stat-label">
            CloudGuard uses Keycloak for centralized identity
            management, authentication and role-based access control.
          </p>

        </section>

        {/* Security Infrastructure */}
        <section className="panel">

          <h2 className="panel-title">
            Security Infrastructure
          </h2>

          <p className="stat-label">
            Audit monitoring, security policy management, and risk
            assessment are connected to the CloudGuard backend.
          </p>

        </section>

      </main>

    </div>
  )
}

export default App
