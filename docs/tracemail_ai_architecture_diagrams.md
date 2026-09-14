# TraceMail AI — Comprehensive Architecture Diagrams

This document contains the complete technical architecture diagrams for **TraceMail AI**, directly reflecting the production code, database schema, threat intelligence integration, and authentication workflows.

---

## 1. High-Level System Architecture

```mermaid
flowchart TB
    subgraph ClientLayer["Presentation Tier (Vercel Edge Network)"]
        UI["Next.js 15 Web Application\n(React 19, TypeScript, Tailwind CSS)"]
        Pages["Views:\n/dashboard | /inbox | /investigation/[id]\n/soc | /evidence | /org | /reports"]
        Zustand["Client State & Auth Store\n(Synchronous localStorage Bearer Token)"]
        UI --- Pages
        UI --- Zustand
    end

    subgraph SecurityBoundary["Security & Ingestion Boundary"]
        OAuth["Google OAuth 2.0\nScope: gmail.readonly"]
        EML["RFC 822 / EML\nDirect File Upload"]
    end

    subgraph BackendLayer["Application Tier (Railway Cloud Containers)"]
        FastAPI["FastAPI Application Server (Python 3.12, Uvicorn)"]
        AuthMid["JWT Auth Middleware & Dependency Injection\n(get_current_user, require_auth)"]
        CanonicalAuth["Canonical Authorization Gates\n(verify_mailbox_access, _verify_investigation_access)"]
        
        subgraph CoreEngines["Core Forensic Engines"]
            Parser["Header & MIME Parser\n(Trusted-MTA Boundary Extractor)"]
            IntelGW["Canonical Threat Intel Gateway\n(Asyncio Parallel Workers)"]
            XAIEngine["Explainable AI Engine\n(Mathematical Scoring & Reason Weights)"]
            EvidenceSvc["Evidence Service\n(SHA-256 Custody Sealer)"]
        end

        FastAPI --> AuthMid
        AuthMid --> CanonicalAuth
        CanonicalAuth --> CoreEngines
    end

    subgraph ThreatIntelCloud["External Threat Intelligence & AI APIs"]
        VT["VirusTotal v3\n(File Hashes & URLs)"]
        Abuse["AbuseIPDB v2\n(IP Reputation & Abuse %)"]
        IPInfo["IPinfo / GeoIP\n(ASN, ISP, Coordinates)"]
        URLScan["URLScan.io\n(Sandbox & Redirects)"]
        GSB["Google Safe Browsing v4\n(Phishing Blacklists)"]
        RDAP["ICANN RDAP / WHOIS\n(Domain Age & Registrar)"]
        DNS["DNSSEC / dnspython\n(SPF, DKIM, DMARC)"]
        Groq["Groq Cloud\n(LLaMA-3 Executive Summaries)"]
        GMaps["Google Maps Platform\n(OSINT & Route Polylines)"]
    end

    subgraph DataStorageTier["Persistence Tier (PostgreSQL 16 on Railway)"]
        Postgres[(PostgreSQL 16 Relational DB\n16 Normalized Tables\nRow-Level Locking with_for_update)]
    end

    UI -->|HTTPS / TLS 1.3 + JWT| FastAPI
    OAuth -.->|Access Tokens| BackendLayer
    EML -.->|Multipart Form Data| BackendLayer
    
    IntelGW --> VT & Abuse & IPInfo & URLScan & GSB & RDAP & DNS & GMaps
    XAIEngine --> Groq
    
    CoreEngines <-->|SQLAlchemy ORM + Connection Pooling| Postgres
```

---

## 2. Investigation Pipeline / Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Security Analyst
    participant UI as Next.js Web Client
    participant API as FastAPI Backend
    participant Parser as HeaderParser (MTA Engine)
    participant IntelGW as ThreatIntel Gateway
    participant XAI as Explainability Engine
    participant Groq as Groq LLaMA-3 AI
    participant Evid as Evidence Locker
    participant DB as PostgreSQL 16 DB

    Analyst->>UI: Submit EML File OR Trigger On-Demand Gmail Scan
    UI->>API: POST /api/investigations OR /api/inbox/messages/{id}/investigate (Bearer JWT)
    
    Note over API,DB: Canonical Authorization: verify_mailbox_access / user identity
    API->>DB: Query existing record with row-level lock (with_for_update)
    
    API->>Parser: Parse RFC 5322 Headers & Multipart Body
    Parser->>Parser: Detect Display-Name Spoofing & Channel Mismatches
    Parser->>Parser: Traverse Received headers top-down to find earliest trusted MX hop
    Parser->>Parser: Extract socket peer IP & validate public IPv4 (_is_public_ip)
    Parser-->>API: Emits Origin IP, Sender FQDN, IOC Entities, Authentication Tokens
    
    par Multi-Provider Threat Intelligence Enrichment
        API->>IntelGW: Query VirusTotal v3 (Attachments & URLs)
        API->>IntelGW: Query AbuseIPDB v2 (IP Abuse Confidence)
        API->>IntelGW: Query IPinfo (ASN, ISP, Country, Coordinates)
        API->>IntelGW: Query URLScan.io & Google Safe Browsing
        API->>IntelGW: Query ICANN RDAP / WHOIS (Domain Age)
        API->>IntelGW: Query DNS Resolver (Live SPF, DKIM, DMARC)
    end
    IntelGW-->>API: Normalized Composite Threat Intelligence Payload

    API->>XAI: Calculate Deterministic Threat Weights (0-100)
    Note over XAI: Weights: Auth (30%) + Domain Age (20%) + Intel (30%) + Heuristics (20%)
    XAI-->>API: Structured Metric Reasons & Threat Verdict (Safe / Suspicious / Phishing)

    API->>Groq: Generate Context-Constrained Executive Narrative
    Groq-->>API: Factually Grounded Human-Readable Incident Summary

    API->>Evid: Seal Forensic Evidence Record
    Evid->>Evid: Compute SHA-256(Raw Headers + Body Payload)
    Evid->>DB: Store EvidenceRecord (Original Hash, Timestamp, Custody Step 1)
    
    API->>DB: Persist Investigation Case (Verdict, Scores, Maps, IOCs)
    DB-->>API: Commit Transaction
    
    API-->>UI: 200 OK (Full Investigation Payload & Forensic Evidence Hash)
    UI-->>Analyst: Render Interactive Investigation Cockpit & OSINT Map
```

---

## 3. Database Entity Relationship (ER) Diagram (Actual 16 Tables)

```mermaid
erDiagram
    users ||--o{ investigations : "owns (owner_user_id)"
    users ||--o{ gmail_accounts : "links (owner_user_id)"
    users ||--o{ audit_logs : "triggers (user_id)"
    investigations ||--o{ emails : "contains"
    investigations ||--o{ headers : "decomposes into"
    investigations ||--o{ ioc_entities : "extracts"
    investigations ||--o{ threat_results : "enriches with"
    investigations ||--o{ ai_results : "synthesizes"
    investigations ||--o{ evidence_records : "cryptographically seals"
    investigations ||--o{ attachment_scans : "inspects"
    investigations ||--o{ reports : "generates"
    investigations ||--o| investigation_geo_cache : "caches geodata"
    gmail_accounts ||--o{ inbox_scan_results : "monitors (account_email)"

    users {
        string id PK "usr_uuid"
        string email UK
        string password_hash
        string name
        string role "admin / analyst"
        boolean is_active
        datetime created_at
    }

    investigations {
        string id PK "inv_uuid"
        string status "processing / complete / failed"
        string sender
        string recipient
        string subject
        datetime received_at
        string domain
        string ip "Origin Public IP"
        string country
        string city
        json latitude
        json longitude
        integer phishing_score "0 to 100"
        string verdict "safe / suspicious / phishing"
        string risk_level "Low / Medium / High / Critical"
        text explanation
        text ai_summary
        text raw_headers
        text body_text
        json entities
        json auth_results
        json hop_timeline
        json timeline
        json geojson_map
        json attack_graph
        json threat_results
        json virus_total
        json abuse_ipdb
        json whois
        json dns
        json urlscan
        json google_safe_browsing
        json ai_analysis
        json ioc
        string evidence_hash "SHA-256"
        json action_items
        string owner_user_id FK "Indexed Tenant Boundary"
        datetime created_at
        datetime updated_at
    }

    gmail_accounts {
        string id PK "gacc_uuid"
        string email UK
        string owner_user_id FK "Indexed Tenant Boundary"
        text access_token
        text refresh_token
        datetime token_expiry
        boolean connected
        datetime created_at
        datetime last_scanned_at
    }

    inbox_scan_results {
        string id PK "inb_uuid"
        string account_email FK
        string message_id
        string sender
        string subject
        text snippet
        string risk "Safe / Suspicious / Critical"
        integer threat_score
        string verdict
        datetime scanned_at
        string investigation_id FK
    }

    evidence_records {
        string id PK "evd_uuid"
        string investigation_id FK
        string sha256 "Current Hash"
        string original_hash "Immutable Ingestion Seal"
        string investigator
        string status "Verified / Tampered / Exported"
        text raw_content
        datetime created_at
        datetime verified_at
        text custody_notes
    }

    attachment_scans {
        string id PK "att_uuid"
        string investigation_id FK
        string filename
        string file_type
        string sha256
        integer size_bytes
        boolean malicious
        string verdict
        string engine
        json details
        datetime created_at
    }

    emails {
        string id PK "eml_uuid"
        string investigation_id FK
        string raw_eml
        text parsed_body
        datetime ingested_at
    }

    headers {
        string id PK "hdr_uuid"
        string investigation_id FK
        string header_key
        text header_value
    }

    ioc_entities {
        string id PK "ioc_uuid"
        string investigation_id FK
        string entity_type "ip / domain / url / hash"
        string entity_value
        string reputation
    }

    threat_results {
        string id PK "thr_uuid"
        string investigation_id FK
        string provider "virustotal / abuseipdb / urlscan"
        json result_payload
        datetime queried_at
    }

    ai_results {
        string id PK "air_uuid"
        string investigation_id FK
        json reason_weights
        text narrative_summary
        datetime generated_at
    }

    reports {
        string id PK "rep_uuid"
        string investigation_id FK
        string report_type "pdf / json / html"
        string file_path
        datetime generated_at
    }

    audit_logs {
        string id PK "aud_uuid"
        string user_id FK
        string action
        string target_resource
        datetime timestamp
    }

    investigation_geo_cache {
        string id PK "geo_uuid"
        string investigation_id FK
        json coordinates
        json polylines
        datetime cached_at
    }

    scans {
        string id PK "scn_uuid"
        string scan_target
        string scan_status
        datetime initiated_at
    }

    org_metrics {
        string id PK "org_uuid"
        string department UK
        integer threat_count
        integer phishing_count
        integer safe_count
        string risk_level
        string top_attack_type
        datetime last_attack_at
    }
```

---

## 4. Tenant Isolation & Authentication Flow Diagram

```mermaid
flowchart TD
    Req([Incoming HTTP Request]) --> AuthHeaderCheck{Authorization Header Present?}
    
    AuthHeaderCheck -- No --> PublicRouteCheck{Is Route Public?}
    PublicRouteCheck -- Yes e.g. /health, /api/auth/login --> AllowPublic[Execute Endpoint Logic: 200 OK]
    PublicRouteCheck -- No e.g. /api/investigations, /api/inbox/* --> Return401[Reject: 401 Unauthorized]

    AuthHeaderCheck -- Yes --> ValidateJWT{Verify JWT Signature & Expiry}
    ValidateJWT -- Invalid / Expired --> Return401Invalid[Reject: 401 Unauthorized]
    ValidateJWT -- Valid Token --> ExtractUser[Extract User Identity & Role: current_user]

    ExtractUser --> RouteTypeCheck{Target Endpoint Resource Type}

    subgraph AdminGate["Administrative Access Control"]
        RouteTypeCheck -- Admin Route e.g. /api/v1/admin/* --> CheckAdminRole{current_user.role == 'admin'?}
        CheckAdminRole -- No (Analyst) --> Return403Admin[Reject: 403 Forbidden]
        CheckAdminRole -- Yes --> AllowAdmin[Execute Admin Action: 200 OK]
    end

    subgraph MailboxGate["Mailbox Ownership Access Control (verify_mailbox_access)"]
        RouteTypeCheck -- Mailbox Route e.g. /api/inbox/scan, /results --> ResolveMailbox[Resolve Target Mailbox from Param or User ID]
        ResolveMailbox --> MailboxExists{Mailbox Found in DB?}
        MailboxExists -- No --> Return404Mailbox[Reject: 404 Not Found]
        MailboxExists -- Yes --> CheckMailboxAdmin{current_user.role == 'admin'?}
        CheckMailboxAdmin -- Yes --> AllowMailbox[Grant Global Admin Access: 200 OK]
        CheckMailboxAdmin -- No --> CheckOwnership{account.owner_user_id == current_user.id OR account.email == current_user.email?}
        CheckOwnership -- No (Stranger Tenant) --> Return403Mailbox[Reject: 403 Forbidden Tenant Boundary Violation]
        CheckOwnership -- Yes --> AllowMailboxAccess[Allow Mailbox Scan & Inspection: 200 OK]
    end

    subgraph InvestigationGate["Case Ownership Access Control (_verify_investigation_access)"]
        RouteTypeCheck -- Case Route e.g. /api/investigations/{id} --> QueryInv[Lookup Investigation by ID in DB]
        QueryInv --> InvExists{Investigation Found in DB?}
        InvExists -- No --> Return404Case[Reject: 404 Not Found]
        InvExists -- Yes --> CheckInvOwner{inv.owner_user_id == None OR inv.owner_user_id == current_user.id OR role == 'admin'?}
        CheckInvOwner -- No (Other Tenant Case) --> Return404Silent[Reject: 404 Not Found Anti-Enumeration]
        CheckInvOwner -- Yes --> AllowCase[Return Investigation Forensics: 200 OK]
    end
```

---

## 5. Trusted-MTA Origin-IP Extraction Diagram (RFC 5322 Spoofing Resistance)

```mermaid
flowchart TD
    RawEML([Raw RFC 822 Email Headers]) --> ExtractHops[Extract All 'Received:' Headers in Chronological Order]

    subgraph AttackerVulnerability["Vulnerability in Naive Email Parsers"]
        DirectionNaive["Naive Parsing Strategy: Select Bottom-Most Hop (Hop 1)"]
        ForgedHeader["Received: from forged-victim.bank.com (1.2.3.4) by attacker.relay.net"]
        FalseAttribution["CRITICAL FAILURE: Innocents Masqueraded as Attacker\nAttacker IP Evades Blacklists"]
        DirectionNaive --> ForgedHeader --> FalseAttribution
    end

    subgraph TraceMailSolution["TraceMail AI Trusted-MTA Boundary Traversal"]
        ScanTopDown[Scan All Hops from Top to Bottom]
        
        HopN["Hop N (Top): Received by internal recipient mail server"]
        Hop2["Hop 2: Received by mx.google.com from attacker.relay.net (198.51.100.55)"]
        Hop1["Hop 1 (Bottom): Received by attacker.relay.net from forged-victim.bank.com (1.2.3.4)"]
        
        ScanTopDown --> HopN --> Hop2 --> Hop1
        
        MatchTrustedBoundary{Does 'by' server match TRUSTED_MTA_PATTERNS?\n(mx.google.com, mx.microsoft.com, pphosted.com, mimecast.com, etc.)}
        
        Hop2 -.-> MatchTrustedBoundary
        MatchTrustedBoundary -- Match Found --> SelectBoundaryHop[Anchor on Earliest Trusted Destination Hop]
        
        SelectBoundaryHop --> ExtractTCPClientIP["Extract IP from 'from ... [IP]' clause stamped by Destination MX\n(e.g., 198.51.100.55)"]
        
        ExtractTCPClientIP --> ValidatePublicIP{_is_public_ip(IP)?\n(Filters 10.x, 172.16-31.x, 192.168.x, 127.x)}
        
        ValidatePublicIP -- Public IP Verified --> SetOriginIP[True Threat Origin Public IP Identified: 198.51.100.55]
        ValidatePublicIP -- Internal/Private --> FallbackTopDown[Traverse Top-Down to First External Public IP]
    end

    ExtractHops --> ScanTopDown
    SetOriginIP --> ThreatIntelFeeds[Pass Genuine Origin IP to AbuseIPDB & GeoIP Services]
```
