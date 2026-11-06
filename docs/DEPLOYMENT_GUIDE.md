# AI-SHIELD — Deployment & Operations Guide

## 1. Production Architecture Overview

AI-SHIELD is designed for single-tenant SME deployments or multi-tenant managed security service providers (MSSPs). It consists of:
- **Core API Gateway:** Flask application with Gunicorn / Waitress WSGI server.
- **Security Operations UI:** React 19 application compiled into static assets served via Nginx or Vite.
- **Database Layer:** Supabase PostgreSQL cloud instance paired with automatic local SQLite WAL persistence.
- **ML Anomaly Engine:** Scikit-Learn `IsolationForest` pipeline serialized in Joblib format.

---

## 2. Prerequisites & Environment Setup

### System Requirements:
- **Operating System:** Linux (Ubuntu 22.04 LTS recommended) or Windows Server 2022+
- **Python:** 3.10+ (Tested on 3.14.3)
- **Node.js:** 18+ (Tested on 24.20.0 with npm 11.x)
- **Supabase PostgreSQL:** Managed instance with Service Role Key access

---

## 3. Database Migration Deployment

To deploy the multi-tenant database schema to your Supabase PostgreSQL instance:

1. Open the [Supabase Dashboard](https://supabase.com/dashboard) and select your project.
2. Navigate to the **SQL Editor** in the left sidebar.
3. Open `backend/migrations/003_multi_tenant_production_schema.sql` in your editor.
4. Paste the entire contents into the SQL Editor and click **Run**.
5. Verify schema status from the terminal:
   ```bash
   python backend/cli.py check-db
   ```
   All 11 tables should report `in_supabase: True`.

---

## 4. Production Secrets & Configuration

Create `backend/.env` with production-grade secrets (ensure `backend/.env` is never committed to Git):

```ini
# Supabase PostgreSQL Configuration
SUPABASE_URL=https://<your-project-id>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<your-high-entropy-service-role-key>

# Application Execution Mode
ENV=production
FLASK_ENV=production
FLASK_DEBUG=0
PERSISTENCE_MODE=dual

# Server Binding
HOST=0.0.0.0
PORT=5000

# Cryptographic Keys (Generate with: python -c "import secrets; print(secrets.token_hex(32))")
SECRET_KEY=<64-character-random-hex-string>
JWT_SECRET_KEY=<64-character-random-hex-string>

# CORS & Domain Boundaries (Restrict to your UI domain)
CORS_ORIGIN=https://shield.yourcompany.com

# Security Policy Thresholds
AGENT_VIOLATION_THRESHOLD=3
RATE_LIMIT_BURST=120
RATE_LIMIT_WINDOW=60
```

---

## 5. Secure Administrator Bootstrapping

In production (`ENV=production`), hardcoded default credentials are disabled. Bootstrap the initial organization administrator via the secure CLI:

```bash
python backend/cli.py init-admin \
  --username secops_admin \
  --email admin@enterprise.com \
  --password "YourStrongProductionPassword2026!" \
  --org-id org_default
```

---

## 6. Backend WSGI Server Execution

### Linux (Gunicorn Multi-Worker)
```bash
# Navigate to backend directory
cd backend

# Install dependencies
pip install -r requirements.txt

# Run with Gunicorn (4 workers, gevent or gthread)
gunicorn --workers 4 --threads 2 --bind 0.0.0.0:5000 "backend.app:create_app()"
```

### Windows (Waitress Production WSGI)
```bash
pip install waitress
waitress-serve --listen=0.0.0.0:5000 "backend.app:create_app()"
```

### Local Development / Evaluation
```bash
python backend/app.py
```

---

## 7. Frontend Production Deployment

### Option A: Static Web Server (Nginx / Cloudflare Pages / S3)
```bash
cd frontend
npm.cmd install
npm.cmd run build
```
Deploy the generated `frontend/dist/` directory to any static file hosting service.

### Option B: Local Production Preview
```bash
cd frontend
npm.cmd run preview -- --host 0.0.0.0 --port 5173
```

---

## 8. Reverse Proxy Configuration (Nginx)

Place Nginx in front of the application for SSL/TLS termination, rate limiting, and static file serving:

```nginx
server {
    listen 443 ssl http2;
    server_name shield.yourcompany.com;

    ssl_certificate /etc/letsencrypt/live/shield.yourcompany.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/shield.yourcompany.com/privkey.pem;

    # Static Frontend
    location / {
        root /var/www/ai-shield/frontend/dist;
        try_files $uri $uri/ /index.html;
    }

    # API Proxy
    location /api/ {
        proxy_pass http://127.0.0.1:5000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 9. Health & Monitoring Checklist

1. **API Health Check:** Query `GET /api/health` and verify `status: "healthy"` and `active_backend: "supabase"`.
2. **Database Status:** Run `python backend/cli.py check-db` regularly or via cron to detect schema drift.
3. **Quarantine Directory:** Ensure `backend/quarantine/` has strict OS permissions (`chmod 700`).
4. **Log Auditing:** Monitor `backend/data/aishield_local.db` file growth and run SQLite `VACUUM` periodically if failover usage is heavy.
