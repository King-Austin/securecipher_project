# Backend Docker Setup

This repository includes Docker support for the backend services only:
- `server` (Django banking API)
- `middleware` (Django gateway)

## Files
- `docker-compose.yml` — orchestrates `db`, `server`, and `middleware`
- `server/Dockerfile` — builds the banking API image
- `middleware/Dockerfile` — builds the gateway image
- `.env.backend.example` — example environment variables for local development

## Local development
1. Copy the example env file:
   ```powershell
   cp .env.backend.example .env
   ```
2. Start the backend stack:
   ```powershell
   docker compose up --build
   ```

## Service ports
- `server`: `http://localhost:8001`
- `middleware`: `http://localhost:8000`
- `db` (PostgreSQL): `localhost:5432`

## Notes
- The frontend and admin apps are not included in this Docker setup.
- If you are hosting frontend/admin separately (for example on Vercel), point their API calls to the middleware endpoint.
- The `middleware` service is configured to use `http://server:8001` internally for the banking API.
