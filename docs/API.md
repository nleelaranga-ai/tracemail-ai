# 📡 TraceMail AI — REST API Specification

This document provides the complete API reference for the TraceMail AI Backend Gateway.

**Base URLs**:
- Local Development: `http://localhost:8000`
- Threat Microservice: `http://localhost:8001`
- Swagger Interactive Docs: `http://localhost:8000/docs`
- ReDoc Documentation: `http://localhost:8000/redoc`

---

## 1. Authentication Endpoints

### 1.1 User Registration
- **Endpoint**: `POST /api/v1/auth/register` (also alias `/api/auth/register`)
- **Headers**: `Content-Type: application/json`
- **Request Body**:
```json
{
  "email": "analyst@cybercell.gov.in",
  "password": "SecurePassword123!",
  "name": "SOC Analyst"
}
```
- **Response** (`201 Created`):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "usr_9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "email": "analyst@cybercell.gov.in",
    "name": "SOC Analyst",
    "role": "analyst"
  }
}
```

### 1.2 User Login
- **Endpoint**: `POST /api/v1/auth/login` (also alias `/api/auth/login`)
- **Request Body**:
```json
{
  "email": "analyst@cybercell.gov.in",
  "password": "SecurePassword123!"
}
```
- **Response** (`200 OK`):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "usr_9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "email": "analyst@cybercell.gov.in",
    "name": "SOC Analyst",
    "role": "analyst"
  }
}
```

---

## 2. Investigation & Email Upload Endpoints

### 2.1 Upload Email (.eml)
- **Endpoint**: `POST /api/investigations` (also `/api/v1/email/upload`)
- **Content-Type**: `multipart/form-data`
- **Form Fields**: `file` (Binary `.eml` or RFC 822 file)
- **Response** (`202 Accepted` / `200 OK`):
```json
{
  "investigationId": "inv_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "status": "complete"
}
```

### 2.2 List Investigations
- **Endpoint**: `GET /api/investigations`
- **Response** (`200 OK`):
```json
[
  {
    "id": "inv_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "status": "complete",
    "sender": "support@paypal-security-update.com",
    "subject": "Urgent: Account Suspended",
    "receivedAt": "2026-09-07T14:30:00Z",
    "verdict": "phishing",
    "phishingScore": 94
  }
]
```

### 2.3 Get Full Investigation (Master Contract)
- **Endpoint**: `GET /api/investigations/{id}`
- **Response** (`200 OK`):
```json
{
  "id": "inv_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "status": "complete",
  "sender": "support@paypal-security-update.com",
  "subject": "Urgent: Account Suspended",
  "receivedAt": "2026-09-07T14:30:00Z",
  "aiResult": {
    "phishingScore": 94,
    "verdict": "phishing",
    "explanation": "Detected critical credential harvesting patterns and domain typosquatting.",
    "entities": {
      "urls": ["http://paypa1-secure.com/login"],
      "ips": ["185.220.101.4"],
      "domains": ["paypa1-secure.com"],
      "senderClaim": "PayPal Support <support@paypal.com>",
      "senderActual": "unknown@sketchy-relay.net"
    }
  },
  "threatResults": [
    {
      "type": "ip",
      "value": "185.220.101.4",
      "reputation": 92,
      "geo": "Frankfurt, Germany",
      "malicious": true
    },
    {
      "type": "url",
      "value": "http://paypa1-secure.com/login",
      "reputation": 95,
      "geo": "Germany",
      "malicious": true
    }
  ],
  "mapUrl": "/api/geo/map/inv_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "timelineUrl": "/api/geo/timeline/inv_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "graphUrl": "/api/geo/graph/inv_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "reportUrl": "/api/report/pdf/inv_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
}
```

---

## 3. Visualization Endpoints (Maps, Timeline, Graph)

### 3.1 GeoJSON Hop Map
- **Endpoint**: `GET /api/geo/map/{id}`
- **Response**: GeoJSON `FeatureCollection` with `Point` (hops) and `LineString` (paths).

### 3.2 Server Hop Timeline
- **Endpoint**: `GET /api/geo/timeline/{id}`
- **Response**: Chronological array of mail server hops with timestamps and malicious flags.

### 3.3 Attack Graph Topology
- **Endpoint**: `GET /api/geo/graph/{id}`
- **Response**: Node-link graph structure (`nodes` and `edges`) showing sender, relays, and victim.

---

## 4. Report Generation Endpoints

### 4.1 Download PDF Forensic Report
- **Endpoint**: `GET /api/report/pdf/{id}`
- **Response**: `application/pdf` binary stream with headers:
  `Content-Disposition: attachment; filename="TraceMail_Forensic_Report_{id}.pdf"`

### 4.2 Machine-Readable JSON Forensic Report
- **Endpoint**: `GET /api/report/json/{id}`
- **Response**: Comprehensive forensic JSON payload structured for CERT-In ingestion.

---

## 5. Health & Diagnostic Endpoints

### 5.1 System Health
- **Endpoint**: `GET /health`
- **Response**:
```json
{
  "status": "healthy",
  "service": "backend-api",
  "version": "1.0.0",
  "timestamp": "2026-09-07T16:00:00Z"
}
```
