# TRUSTMESH — Microsoft Azure App Service Deployment Guide
**Phase 4, Task 5: Production Cloud Hosting & Deployment Preparation**

---

## 1. Architecture & Production Overview

TRUSTMESH is designed to run in production on **Microsoft Azure App Service (Linux)** using **Gunicorn** as the production WSGI server. The architecture supports both local development and scalable cloud hosting:

```
                                  +---------------------------------------+
                                  |            Client Browser             |
                                  |     (HTTPS on *.azurewebsites.net)    |
                                  +-------------------+-------------------+
                                                      |
                                                      | TLS / HTTPS (Port 443)
                                                      v
                                  +---------------------------------------+
                                  |     Azure Front-End / Load Balancer   |
                                  |       (SSL Termination & Routing)     |
                                  +-------------------+-------------------+
                                                      |
                                                      | HTTP (Port 8000)
                                                      v
                                  +---------------------------------------+
                                  |     Azure App Service Linux Container |
                                  |    (Python 3.12 Runtime / Oryx Build) |
                                  |                                       |
                                  |  +---------------------------------+  |
                                  |  | Gunicorn WSGI Server            |  |
                                  |  | (2 Workers, 4 Threads, 120s TO) |  |
                                  |  | Command: bash startup.sh        |  |
                                  |  +----------------+----------------+  |
                                  |                   |                   |
                                  |                   v                   |
                                  |  +---------------------------------+  |
                                  |  | Flask Application Instance      |  |
                                  |  | (config.ProductionConfig)       |  |
                                  |  | - Debug: False                  |  |
                                  |  | - Secure Cookies: True          |  |
                                  |  | - Max Upload: 16 MB             |  |
                                  |  +----------------+----------------+  |
                                  +-------------------|-------------------+
                                                      |
                             +------------------------+------------------------+
                             |                                                 |
                             v                                                 v
             +-------------------------------+                 +-------------------------------+
             |   Azure SQL Database (Cloud)  |                 |   Azure Blob Storage (Cloud)  |
             |  - Relational tables & views  |                 |  - Private container reports  |
             |  - Fallback: Local SQLite     |                 |  - Fallback: Local downloads  |
             +-------------------------------+                 +-------------------------------+
```

---

## 2. Student Cost Protection & Free-Tier Plan Selection

> [!IMPORTANT]
> **Zero-Cost Student Policy:** As a student, you should never accidentally provision paid cloud tiers. Follow these rules to keep hosting 100% free:
> - **Azure for Students Subscription:** Provides **\$100 in free Azure credits** without requiring a credit card, plus 12 months of free popular services.
> - **App Service Plan SKU:** Select the **Free F1 Tier** (Linux) or **Shared D1 Tier**.
>   * **F1 Free Plan:** 1 GB RAM, 60 CPU minutes per day, free custom domain SSL via `*.azurewebsites.net`.
>   * **Basic B1 Plan (Optional):** If using free university credits, the B1 tier (~$12/month deducted from credits) provides dedicated compute without daily CPU minute caps.
> - **Never** select Standard (S1), Premium (P1v2/P1v3), or Isolated plans.

---

## 3. Prerequisites

Before deploying, ensure you have:
1. An active [Azure Account](https://azure.microsoft.com/free/students/) (free student account or university subscription).
2. The [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) installed locally, or access to the [Azure Portal](https://portal.azure.com/).
3. Git installed and the TRUSTMESH codebase ready.
4. Python 3.12 (or 3.11).

---

## 4. Deployment Files in the Repository

TRUSTMESH includes all required deployment configuration files:

| File | Purpose |
| :--- | :--- |
| [startup.sh](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/startup.sh) | Production entry point script for Azure App Service Linux. Starts Gunicorn with dynamic port binding, 2 workers, and 4 threads. |
| [.deployment](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/.deployment) | Azure Oryx build configuration directing Azure to automatically install `requirements.txt` during deployment. |
| [config.py](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/config.py) | Centralized environment profiles (`ProductionConfig`, `DevelopmentConfig`, `TestingConfig`). |
| [wsgi.py](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/wsgi.py) | Standard WSGI callable entry point (`wsgi:app`). |
| [requirements.txt](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/requirements.txt) | Python dependencies including `Flask`, `Flask-WTF`, `SQLAlchemy`, `gunicorn`, and `azure-storage-blob`. |
| [.env.example](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/.env.example) | Template documenting all environment variables for App Service Configuration. |

---

## 5. Step-by-Step Deployment Instructions

### Step 1: Create the Azure App Service (Portal Method)

1. Log in to the [Azure Portal](https://portal.azure.com/).
2. In the search bar, search for **App Services** and click **Create** -> **Web App**.
3. Configure the **Basics** tab:
   - **Subscription:** Select your *Azure for Students* or *Pay-As-You-Go* subscription.
   - **Resource Group:** Click *Create new* and enter `trustmesh-rg`.
   - **Name:** Enter a globally unique name, e.g., `trustmesh-app` (your URL will be `https://trustmesh-app.azurewebsites.net`).
   - **Publish:** Select **Code**.
   - **Runtime stack:** Select **Python 3.12** (or **Python 3.11**).
   - **Operating System:** Select **Linux**.
   - **Region:** Select a region close to you (e.g., *East US*, *Central India*, *West Europe*).
   - **Pricing Plan:** Click *Change size* -> select **Dev / Test** tab -> choose **F1 (Free)** (or **B1** if using student credits).
4. Click **Review + create** -> click **Create**. Wait ~1 minute for provisioning.

---

### Step 2: Configure Environment Variables (Application Settings)

In the Azure Portal, open your new Web App (`trustmesh-app`):
1. In the left navigation menu, under **Settings**, select **Environment variables** (or **Configuration** -> **Application settings**).
2. Add the following key-value pairs by clicking **+ Add**:

| Name | Recommended Value | Description |
| :--- | :--- | :--- |
| `FLASK_ENV` | `production` | Activates `ProductionConfig` (disables debug mode, enforces HTTPS cookies). |
| `SECRET_KEY` | *(Generate 64 hex chars)* | Cryptographic key for session signing and CSRF tokens. |
| `COOKIE_SECURE` | `true` | Enforces that session cookies are only transmitted over HTTPS. |
| `DATABASE_MODE` | `sqlite` or `azure_sql` | Set to `azure_sql` for persistent cloud DB, or `sqlite` for standalone evaluation. |
| `PORT` | `8000` | Internal listening port. Azure routes external port 443/80 to this port. |
| `GUNICORN_WORKERS` | `2` | Number of worker processes. |
| `GUNICORN_THREADS` | `4` | Number of threads per worker. |
| `GUNICORN_TIMEOUT` | `120` | Worker timeout in seconds. |

*(Optional Azure SQL Settings — if using Task 2 Cloud DB):*
- `AZURE_SQL_SERVER`: `your-server.database.windows.net`
- `AZURE_SQL_DATABASE`: `trustmesh-db`
- `AZURE_SQL_USERNAME`: `your-username`
- `AZURE_SQL_PASSWORD`: `your-password`

*(Optional Blob Storage Settings — if using Task 3 Cloud Storage):*
- `AZURE_STORAGE_ACCOUNT_NAME`: `yourstorageaccount`
- `AZURE_STORAGE_CONTAINER_NAME`: `trustmesh-reports`
- `AZURE_STORAGE_CONNECTION_STRING`: `DefaultEndpointsProtocol=https;...`

3. Click **Apply** (or **Save**) and confirm the restart.

---

### Step 3: Configure the Startup Command

Azure App Service Linux requires the startup script to start Gunicorn:
1. In your Web App's left menu, under **Settings**, select **Configuration** -> click the **General settings** tab.
2. In the **Startup Command** box, enter:
   ```bash
   bash startup.sh
   ```
3. Click **Save** at the top.

---

### Step 4: Deploy the Application Code

You can deploy using either the **Azure CLI (ZIP Deploy)**, **Local Git**, or **VS Code Azure Tools**:

#### Option A: Azure CLI ZIP Deploy (Fastest & Simplest)
From your local terminal in the `TRUST MESH` project directory:
```bash
# 1. Login to Azure
az login

# 2. Deploy your folder directly to the App Service
az webapp deploy --resource-group trustmesh-rg --name trustmesh-app --src-path . --type zip
```

#### Option B: GitHub Actions / Git Deployment
1. Under **Deployment**, select **Deployment Center**.
2. Select **GitHub** as the source, authorize your account, and choose your repository and `master`/`main` branch.
3. Azure automatically creates a `.github/workflows` action that builds and deploys on every `git push`.

---

### Step 5: Verify Deployment and Health Status

1. In the Azure Portal, navigate to **Monitoring** -> **Log stream** to view real-time container output. You should see:
   ```
   [TRUSTMESH] Initiating Azure App Service Linux production startup...
   [TRUSTMESH] Hosting on 0.0.0.0:8000 (Workers: 2, Threads: 4, Timeout: 120s)
   [TRUSTMESH] Environment: production
   [Gunicorn] Starting gunicorn 21.2.0
   [Gunicorn] Listening at: http://0.0.0.0:8000
   ```
2. Open your browser and navigate to the health-check endpoint:
   ```
   https://trustmesh-app.azurewebsites.net/health
   ```
   Expected response:
   ```json
   {
     "status": "healthy",
     "environment": "production",
     "database": "connected",
     "database_mode": "sqlite",
     "database_status_indicator": "Local SQLite connected",
     "storage_status": "not_configured",
     "storage_indicator": "Storage not configured (Local Fallback)",
     "engine_version": "3.0.0"
   }
   ```
3. Open `https://trustmesh-app.azurewebsites.net/` to use the live platform!

---

## 6. Troubleshooting Common Production Issues

### Issue 1: 502 Bad Gateway / Application Error
- **Cause:** Gunicorn failed to start, the startup command was wrong, or a dependency is missing.
- **Diagnosis:** Open **Monitoring** -> **Log stream** in the Azure Portal.
- **Fix:** Ensure **Startup Command** is set to `bash startup.sh`. Ensure `SCM_DO_BUILD_DURING_DEPLOYMENT=true` is present in Application Settings so Oryx runs `pip install -r requirements.txt`.

### Issue 2: Session Logins Lost Immediately (Redirected Back to `/login`)
- **Cause:** `COOKIE_SECURE=true` is set, but the request was accessed over plain `http://` instead of `https://`.
- **Fix:** Always access the site via `https://`. In Azure App Service, navigate to **Configuration** -> **General settings** -> enable **HTTPS Only**.

### Issue 3: SQLite Data Resets After App Restart
- **Cause:** In Azure App Service Linux, local container storage is ephemeral by default. Restarting or scaling the app re-initializes the local container.
- **Fix:** For persistent cloud deployments, switch to **Azure SQL Database** (`DATABASE_MODE=azure_sql`), or enable persistent storage by setting `WEBSITES_ENABLE_APP_SERVICE_STORAGE=true` in Application Settings.

### Issue 4: Database Connection Timeout (Azure SQL)
- **Cause:** Azure SQL firewall is blocking connections from the App Service.
- **Fix:** In the Azure Portal, open your SQL Server -> **Security** -> **Networking** -> check **"Allow Azure services and resources to access this server"** -> click **Save**.

---

## 7. Security Hardening Checklist

- [x] Flask `DEBUG` mode disabled in production (`ProductionConfig.DEBUG = False`).
- [x] `SECRET_KEY` loaded securely from Azure Application Settings (never hardcoded).
- [x] Session cookies configured with `HttpOnly=True`, `SameSite='Lax'`, and `Secure=True`.
- [x] HTTP Strict Security Headers enforced (`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, CSP).
- [x] CSRF protection active on all state-changing endpoints (`Flask-WTF`).
- [x] Payload upload ceiling capped at 16 MB (`MAX_CONTENT_LENGTH`) with a safe 413 error handler.
- [x] Error handlers (400, 403, 404, 413, 500) prevent stack trace leakage.
- [x] Relational queries parameterized to prevent SQL injection.
- [x] Administrative endpoints restricted via `@role_required("admin")`.
- [x] Sensitive passwords and tokens masked in all logs and `/health` responses.

