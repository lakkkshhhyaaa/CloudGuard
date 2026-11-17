
export const PERMISSIONS = {
  overview: [
    'IT_ADMIN',
    'SECURITY_ANALYST',
    'HR_MANAGER',
    'FINANCE_ANALYST',
  ],

  users: [
    'IT_ADMIN',
  ],

  roles: [
    'IT_ADMIN',
    'SECURITY_ANALYST',
  ],

  policies: [
    'IT_ADMIN',
    'SECURITY_ANALYST',
  ],

  events: [
    'IT_ADMIN',
    'SECURITY_ANALYST',
  ],

  risk: [
    'IT_ADMIN',
    'SECURITY_ANALYST',
  ],

  settings: [
    'IT_ADMIN',
  ],
}

export function canAccess(feature, roles = []) {
  const allowedRoles = PERMISSIONS[feature]

  if (!allowedRoles) {
    return false
  }

  return roles.some((role) => allowedRoles.includes(role))
}
