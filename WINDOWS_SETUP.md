# SENTINEL-GRC — Windows Setup Guide

## Prerequisites (one-time install)

### 1. Install Docker Desktop for Windows
1. Go to: **https://www.docker.com/products/docker-desktop/**
2. Download **Docker Desktop for Windows**
3. Run the installer — when asked, choose **"Use WSL 2 based engine"** (recommended)
4. Restart your computer when prompted
5. After restart, open Docker Desktop from the Start Menu and wait until you see **"Docker Desktop is running"** (green icon in system tray)

### 2. Enable PowerShell script execution (one-time)
Open PowerShell **as Administrator** and run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Type `Y` and press Enter.

---

## Starting SENTINEL-GRC

### Step 1 — Extract the ZIP
Right-click `sentinel-grc.zip` → **Extract All** → choose a folder (e.g. `C:\Projects\sentinel-grc`)

### Step 2 — Open PowerShell in that folder
- Navigate to the extracted folder in File Explorer
- Click the address bar, type `powershell`, press Enter
- OR: Hold `Shift` + right-click in the folder → **"Open PowerShell window here"**

### Step 3 — Run the startup script
```powershell
.\start.ps1
```

First run downloads all Docker images (~800MB). This takes **2–5 minutes** depending on your internet speed. Subsequent starts take about **30 seconds**.

The script will automatically open **http://localhost:3000** in your browser when ready.

---

## Login

| Field | Value |
|---|---|
| Email | `admin@sentinel.local` |
| Password | `SentinelAdmin@2024` |

---

## Service URLs

| Service | URL |
|---|---|
| **Dashboard (React)** | http://localhost:3000 |
| **API (FastAPI)** | http://localhost:8000 |
| **API Docs (Swagger)** | http://localhost:8000/api/docs |
| **MinIO Evidence Store** | http://localhost:9001 |

MinIO login: `sentinel_minio` / `sentinel_minio_secret`

---

## Stopping SENTINEL-GRC

```powershell
.\stop.ps1
```

Or to stop AND delete all data (full reset):
```powershell
docker compose down -v
```

---

## First-Time Walkthrough

1. **Log in** at http://localhost:3000

2. **Run the control sweep**
   - Go to **Controls** in the left sidebar
   - Click **"Run Full Sweep Now"**
   - Wait ~10 seconds, then refresh — you'll see pass/fail results for all 12 controls

3. **View auto-created risks**
   - Go to **Risk Register**
   - Any failed controls auto-created risks with FAIR financial calculations
   - Click a row to expand and see the Monte Carlo ALE figure and loss exceedance curve

4. **Refresh threat intelligence**
   - Go to **Threat Intel**
   - Click **"Refresh All Feeds"**
   - SENTINEL will pull the latest CVEs from NVD and CISA KEV

5. **Generate reports**
   - Go to **Reports**
   - Click **"Generate Board Report"** — a professional PDF opens for download
   - Also generate the Auditor and Technical reports

6. **Try the governance workflow**
   - Go to **Governance**
   - Click **"New Policy"**, fill in a title
   - Use the transition buttons to walk it through: Draft → Legal Review → CISO Approval → Published

---

## Troubleshooting

### "Docker daemon is not running"
- Open Docker Desktop from the Start Menu
- Wait for the whale icon in the system tray to stop animating
- Re-run `.\start.ps1`

### "port is already in use"
Another app is using port 3000, 8000, or 5432. Either stop that app or edit `docker-compose.yml` to change the port mappings.

### Containers keep restarting
```powershell
docker compose logs backend
```
Look for error messages. Most common cause: database not ready yet — wait 30 seconds and it will auto-recover.

### Full reset (delete all data and start fresh)
```powershell
.\stop.ps1
docker compose down -v
.\start.ps1
```

### Check container status
```powershell
docker compose ps
```
All 6 containers should show `running` or `healthy`.

---

## Useful Docker Commands

```powershell
# See all logs live
docker compose logs -f

# See only backend logs
docker compose logs -f backend

# See only celery worker logs  
docker compose logs -f celery_worker

# Restart just the backend
docker compose restart backend

# Open a shell inside the backend container
docker compose exec backend bash
```
