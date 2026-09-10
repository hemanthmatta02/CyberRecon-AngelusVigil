# CyberRecon + CyberSentinel

This repository contains the existing CyberSentinel AI threat-detection dashboard extended with a bounded **CyberRecon** module for authorized security assessments.

## Features

- Existing AI threat detection dashboard, threat events and model management
- DNS discovery: A, AAAA, CNAME, MX, NS, TXT and SOA records
- Reverse DNS (PTR) lookups for resolved addresses
- Common subdomain discovery using a bounded candidate list
- Bounded TCP connect checks against selected common ports
- Lightweight HTTP metadata probing (status, title, content type, server/technology hints)
- Persistent recon assessment history in PostgreSQL
- React dashboard page at `/recon`
- Docker Compose stack that runs locally without MaxMind credentials

The recon engine is deliberately limited to discovery and metadata collection. It does not exploit services, brute-force credentials, or attempt authentication bypasses.

## Run on Windows with Docker

From the repository root:

```powershell
docker compose up -d --build
```

The default local URLs are:

- Frontend: http://localhost:46969
- Backend API docs: http://localhost:36969/docs
- Health: http://localhost:36969/health

The frontend proxies API calls to the backend, so you normally only need to open the frontend.

Check services:

```powershell
docker compose ps
docker compose logs --tail=100 backend
```

Stop:

```powershell
docker compose down
```

## CyberRecon

Open **CyberRecon** in the left navigation.

Enter a domain you own or are explicitly authorized to assess, select discovery modules, choose common TCP ports, and start the assessment.

The API endpoints are:

- `POST /recon/scan`
- `GET /recon/history`
- `GET /recon/history/{scan_id}`

Example request:

```json
{
  "domain": "example.com",
  "include_subdomains": true,
  "include_ports": true,
  "include_http": true,
  "ports": [80, 443, 8080]
}
```


## Managed deployment

For a hosted deployment, use a managed application platform instead of running the local Compose lab. The recommended layout is a Railway backend service with managed PostgreSQL and Redis, plus the React frontend on Vercel or as a separate static service. This keeps the database, Redis, HTTP API, and WebSocket endpoint available without requiring Docker Desktop on the deployment machine.

Configure the backend service root directory as `/CyberRecon-AngelusVigil-SOCPlatform/CyberRecon-AngelusVigil-Final/backend` so Railway detects `pyproject.toml`. Set the Railway config file explicitly to `/CyberRecon-AngelusVigil-SOCPlatform/CyberRecon-AngelusVigil-Final/railway.toml`; the file uses Railpack (not a user-managed Dockerfile), starts `python -m app`, and uses `/ready` as the readiness probe. Set these production variables in the platform secret manager:

- `ENV=production`
- `AUTH_SECRET` — a random value of at least 32 characters
- `ALLOW_DEMO_AUTH=false`
- `ALLOW_PUBLIC_REGISTRATION=false`
- `CORS_ORIGINS` — the exact public frontend origin
- `DATABASE_URL` and `REDIS_URL` — supplied by the managed services
- `DEFAULT_ADMIN_PASSWORD`, `DEFAULT_ANALYST_PASSWORD`, and `DEFAULT_VIEWER_PASSWORD` — one-time bootstrap credentials

For a separate frontend service, set its root directory to `CyberRecon-AngelusVigil-SOCPlatform/CyberRecon-AngelusVigil-Final/frontend`, build with `npm run build`, publish `dist`, and configure `VITE_API_URL` to the HTTPS backend URL and `VITE_WS_URL` to the WSS endpoint ending in `/ws/alerts`. After the first admin login, rotate the bootstrap passwords and keep all production secrets out of Git.
## MaxMind GeoIP

GeoIP is optional in this local build. The backend gracefully disables GeoIP lookups when the `.mmdb` database is absent, so no MaxMind account is needed to run the core application or CyberRecon module.

## Data

PostgreSQL stores threat events and completed recon assessments. Docker volumes keep database, Redis, model and other local data across restarts.

## Multi-dashboard SOC platform

The current build is organized into separate operational tabs rather than putting every capability on one dashboard:

- Overview
- Manual Request
- Real-Time Attack Detection
- Threat Intelligence
- ML / AI Analysis
- SOC Operations
- Incident Response
- Attack Simulation
- Asset Discovery
- Reports
- Threat Events
- Models
- CyberRecon

Use `docker compose up -d --build` from the repository root. The compose file now starts the local lab target and nginx proxy on the same Docker network as the backend, so Manual Request and Attack Simulation can exercise the real log-ingestion path without requiring a second compose stack.

The Threat Intelligence page intentionally reports **local observed-telemetry reputation** unless an external feed is configured. It does not pretend that an external commercial feed is present. Likewise, the ML page reports model state and observed scores from the running system rather than inventing accuracy metrics without a labeled evaluation set.
