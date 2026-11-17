
# CloudGuard – Cloud Security & Identity Access Management Platform

CloudGuard is a Dockerized Cloud Security and Identity & Access Management (IAM) platform designed to demonstrate practical identity security, access governance, authentication, authorization, and cloud deployment concepts.

The project aims to simulate an organization's identity environment and implement security controls through a centralized IAM platform.

## Project Objectives

- Implement centralized identity and access management.
- Configure Role-Based Access Control (RBAC).
- Demonstrate Multi-Factor Authentication (MFA).
- Implement Single Sign-On (SSO).
- Apply the Principle of Least Privilege.
- Simulate Joiner, Mover, and Leaver (JML) workflows.
- Maintain identity and access audit logs.
- Perform basic cybersecurity risk assessments.
- Deploy a multi-container application using Docker on AWS.

## Technology Stack

| Technology | Purpose |
|---|---|
| React + Vite | Frontend dashboard |
| Python + FastAPI | Backend API |
| Keycloak | Identity and Access Management |
| PostgreSQL | Database |
| Docker | Containerization |
| Docker Compose | Container orchestration |
| Nginx | Reverse proxy |
| AWS EC2 | Cloud hosting |
| Ubuntu Linux | Server environment |
| Git & GitHub | Version control |

## Planned Features

### 1. Identity Management
- User provisioning and deprovisioning.
- User groups and organizational roles.
- Centralized identity management.

### 2. Access Control
- Role-Based Access Control (RBAC).
- Least privilege enforcement.
- Permission management.

### 3. Authentication
- Multi-Factor Authentication.
- Single Sign-On.
- Centralized authentication through Keycloak.

### 4. User Lifecycle Management
- Joiner: onboarding new employees.
- Mover: modifying permissions when employees change roles.
- Leaver: revoking access when employees leave.

### 5. Security Monitoring
- Identity and access audit logs.
- Access activity monitoring.
- Access review mechanisms.

### 6. Risk Assessment
- Asset inventory.
- Threat identification.
- Risk register.
- Security recommendations.

## Project Architecture

The application will use a multi-container architecture managed through Docker Compose.

Planned services:

- Frontend: React application.
- Backend: FastAPI application.
- Identity Provider: Keycloak.
- Database: PostgreSQL.
- Reverse Proxy: Nginx.

## Project Structure

```text
CloudGuard/
├── backend/
├── frontend/
├── config/
├── scripts/
├── policies/
├── risk-assessment/
├── logs/
├── reports/
├── screenshots/
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

## Deployment

The planned deployment environment is:

- AWS EC2
- Ubuntu Linux
- Docker Engine
- Docker Compose
- HTTPS-enabled public access

The application will be accessible through a public HTTPS URL after deployment.

## Security Considerations

- Secrets will be stored outside version control.
- Database services will not be exposed publicly.
- Administrative interfaces will require authentication.
- Network access will be restricted.
- HTTPS will be configured for public deployment.
- Synthetic test identities will be used.

## Project Status

**Status: Initial Development**

Environment preparation and project structure have been established. Application development, integration, testing, and cloud deployment are planned development milestones.

## Learning Outcomes

This project is intended to demonstrate practical understanding of:

- Identity and Access Management.
- Authentication and Authorization.
- RBAC and Least Privilege.
- MFA and SSO.
- Joiner, Mover, and Leaver workflows.
- Docker and container orchestration.
- Linux administration.
- AWS cloud infrastructure.
- Security auditing and risk assessment.

---

**CloudGuard**  
Cloud Security | Identity & Access Management | Docker | AWS



alex: CloudGuard!Alex2027#Temp
Sarah: CloudGuard!Sarah2027#Temp
Emma: CloudGuard!Emma2027#Temp
James: CloudGuard!James2027#Temp

