# 🛠️ TraceMail AI — Setup & Installation Guide

This guide walks through configuring and running TraceMail AI locally or using Docker.

---

## 1. Prerequisites

- **Python**: 3.11 or 3.12
- **Node.js**: 18 LTS or 22 LTS
- **Docker & Docker Compose**: (Optional for multi-container orchestration)
- **Git**

---

## 2. Fast Track: Single-Command Setup

Run the automated cross-platform setup script from the root of the repository:

### Windows (PowerShell):
```powershell
.\scripts\setup\setup.ps1
```

### Linux / macOS:
```bash
bash scripts/setup/setup.sh
```

This will automatically create virtual environments, install Python dependencies, setup `.env`, and prepare sample fixtures.

---

## 3. Manual Microservices Setup

### 3.1 Backend Setup
```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Backend API will be live at `http://localhost:8000`.  
Swagger documentation is available at `http://localhost:8000/docs`.

### 3.2 Threat Intelligence Setup
```bash
cd threat_intelligence
uvicorn service:app --reload --port 8001
```
Threat Intelligence microservice will be live at `http://localhost:8001`.

### 3.3 Frontend Setup (Next.js 15)
```bash
cd frontend
npm install
npm run dev
```
Frontend web interface will be live at `http://localhost:3000`.

---

## 4. Docker Multi-Service Orchestration

To run the entire suite with PostgreSQL, Redis, and all microservices in a single command:

```bash
docker-compose up --build
```

### Exposed Service Ports:
- **Frontend Dashboard**: `http://localhost:3000`
- **Backend API Gateway**: `http://localhost:8000`
- **Threat Intelligence Engine**: `http://localhost:8001`
- **PostgreSQL Database**: `localhost:5432`
- **Neo4j Graph Database**: `localhost:7474` (Bolt: `7687`)
