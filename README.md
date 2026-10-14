# CoreWorks

CoreWorks is a modular IT platform for identity, infrastructure monitoring, and security assessment.

## Platform Modules

### CoreWorks Hub
Central portal, dashboard, and navigation for the CoreWorks platform.

### CoreWorks ID
User identity, authentication, access management, administration, and licensing.

### CoreWorks Monitor
Infrastructure monitoring for registered hosts, including status checks, metrics, and agent-based data collection.

### CoreWorks Guardian
An independent security assessment module for network scanning, scan history, findings, and security recommendations.

Guardian is developed as a new CoreWorks module. It does not reuse or embed the existing VELES implementation.

## Technology Stack

- Frontend: Next.js, React, TypeScript
- Backend: Python, FastAPI
- Database: PostgreSQL
- ORM: SQLAlchemy
- Database migrations: Alembic

## Repository Structure

- `backend/agent/` — monitoring agent
- `backend/coreworks_api/` — backend API and modules
- `backend/migrations/` — database migrations
- `backend/tests/` — backend tests
- `frontend/src/app/` — application pages
- `frontend/src/components/` — shared UI components
- `frontend/src/lib/` — frontend utilities and API client

## Development Requirements

- Python and pip
- Node.js and npm
- PostgreSQL
- Backend and frontend environment configuration

Install backend dependencies from `backend/requirements.txt`. Install frontend dependencies from `frontend/package.json` using `npm install` in the `frontend` directory.

Configure the database and required environment variables before starting the API. Apply database migrations using the project's configured Alembic environment. Start the frontend with `npm run dev` from the `frontend` directory.

Run backend tests with `python -m pytest` from the `backend` directory, using the project's configured Python environment.

## Security

- Never commit secrets, passwords, private keys, or production environment files.
- Use HTTPS in production.
- Restrict database and internal service access.
- Back up the database before production migrations.
- Review Guardian findings in the context of the assessed environment.

## Project Status

CoreWorks is under active development. Module capabilities and deployment requirements may change as implementation progresses.

## License

Licensing terms will be specified by the project owner.
