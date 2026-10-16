# CoreWorks roadmap

## 1. CoreWorks Hub
- [x] Central portal and module navigation
- [ ] Consolidate portal workflows on the Next.js frontend and FastAPI backend
- [ ] Align dashboard functionality with CoreWorks ID and module permissions

## 2. CoreWorks ID
- [x] PostgreSQL-backed user identity
- [x] Authentication and access-control foundation
- [ ] Complete user administration and account recovery
- [ ] Finalize licensing workflows

## 3. CoreWorks Monitor
- [x] Module routes and frontend integration
- [ ] Server/service health checks
- [ ] Monitoring history and status dashboard
- [ ] Alerting and notifications

## 4. CoreWorks Guardian
- [x] Independent module foundation
- [ ] Network scanning and scan history
- [ ] Findings, severity assessment, and remediation guidance

Guardian is a new, independent CoreWorks implementation. It does not reuse or embed the existing VELES implementation.

## 5. Integrations
- [ ] Define module interfaces and permissions
- [ ] Add integrations after requirements are agreed

## Platform standards
- Frontend: Next.js, React, TypeScript
- Backend: FastAPI
- Database: PostgreSQL
- ORM and migrations: SQLAlchemy and Alembic
- No Flask application or SQLite application database in the active platform
