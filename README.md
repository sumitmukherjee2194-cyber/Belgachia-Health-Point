# Belgachia Health Point – Billing AI

AI-based ERP and billing management system for pharmacies and hospitals. Supports CSV bulk upload from Marg exports, real-time insights, and AI recommendations for billing fixes and optimization.

## Stack
- Backend: FastAPI + Uvicorn (Python)
- Frontend: React 18 via CDN (served as static `index.html` + `dashboard.jsx`)
- Data: CSV uploads, in-memory summaries (plug DB later)
- AI: Optional OpenAI API (fallback to heuristic insights)

## Quick Start
```bash
cp .env.example .env
# Optionally edit OPENAI_API_KEY and JWT_SECRET

./run.sh
# Backend: http://localhost:8000
# Frontend served by backend: http://localhost:8000/
```

Demo users:
- admin / admin123 (Admin)
- manager / manager123 (Manager)
- pharma / pharma123 (Pharmacist)

## Frontend
Static files in `frontend/` are served by the backend:
- `index.html` bootstraps React and loads `dashboard.jsx`
- `dashboard.jsx` handles login (JWT), CSV upload, insights, query, analytics

## API Endpoints
- `POST /auth/login` → body: `{ username, password }` → returns `{ access_token, role, username }`
- `GET /auth/me` (auth)
- `POST /upload-csv?data_type=...` (auth) → multipart with `file`
- `GET /analytics-summary` (auth)
- `POST /generate-insight` (auth)
- `POST /query` (auth)
- `POST /validate-data` (auth)
- `GET /sync-marg-db` (Admin/Manager)
- `POST /auto-fix` (Admin/Manager)
- `GET /generate-report` (Admin/Manager)

Auth header: `Authorization: Bearer <token>`

## Environment
See `.env.example`:
- `HOST`, `PORT` server bind
- `FRONTEND_DIR` path to serve static React files
- `UPLOAD_DIR` CSV save location
- `JWT_SECRET`, `JWT_ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES`
- `OPENAI_API_KEY` (optional), `OPENAI_MODEL`

## Bulk CSV Upload (Marg)
- Export CSV from Marg
- Use UI “Bulk CSV Upload” → choose file and set data type
- Backend stores to `UPLOAD_DIR` and computes quick KPIs

## Development
- Install Python 3.11+
- Script will install Python deps automatically
- Modify `backend/app.py` for APIs and AI logic
- Modify `frontend/index.html` and `frontend/dashboard.jsx` for UI

## Deployment
- Backend (Render): run command `./run.sh`
- Frontend (Vercel): optional, but current setup serves frontend from backend
- Database: plug MongoDB Atlas or PostgreSQL later

## Notes
- If `OPENAI_API_KEY` is not set, insight/query endpoints return heuristic suggestions
- CORS is open by default; tighten for production
