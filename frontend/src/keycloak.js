import Keycloak from 'keycloak-js'

const keycloak = new Keycloak({
  url: 'http://localhost:8080',
  realm: 'cloudguard',
  clientId: 'cloudguard-frontend',
})

export default keycloak