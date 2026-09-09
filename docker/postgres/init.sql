-- TraceMail AI -- Central PostgreSQL 16 Schema Initializer
-- Maintained by Backend Team & Threat Intelligence Team

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users Table (Auth accounts)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'analyst',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Investigations Table
CREATE TABLE IF NOT EXISTS investigations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(50) DEFAULT 'queued',
    subject VARCHAR(500),
    sender VARCHAR(255),
    recipient VARCHAR(255),
    overall_verdict VARCHAR(50),
    overall_score INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Emails Table (Raw + parsed content)
CREATE TABLE IF NOT EXISTS emails (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    raw_eml TEXT,
    body_plain TEXT,
    body_html TEXT,
    message_id VARCHAR(255),
    date_sent TIMESTAMP WITH TIME ZONE
);

-- Headers Table
CREATE TABLE IF NOT EXISTS headers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    raw_headers TEXT,
    spf_status VARCHAR(50),
    dkim_status VARCHAR(50),
    dmarc_status VARCHAR(50),
    return_path VARCHAR(255)
);

-- IP Addresses Table
CREATE TABLE IF NOT EXISTS ip_addresses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    country VARCHAR(100),
    city VARCHAR(100),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    isp VARCHAR(255),
    asn VARCHAR(50),
    abuse_score INT DEFAULT 0,
    is_malicious BOOLEAN DEFAULT FALSE,
    hop_order INT DEFAULT 0
);

-- URLs Table
CREATE TABLE IF NOT EXISTS urls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    domain VARCHAR(255),
    is_malicious BOOLEAN DEFAULT FALSE,
    category VARCHAR(100) DEFAULT 'clean',
    vt_positives INT DEFAULT 0,
    vt_total INT DEFAULT 0
);

-- AI Results Table
CREATE TABLE IF NOT EXISTS ai_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    phishing_score INT DEFAULT 0,
    verdict VARCHAR(50),
    explanation TEXT,
    extracted_entities JSONB
);

-- Threat Results Table
CREATE TABLE IF NOT EXISTS threat_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    risk_level VARCHAR(50),
    risk_score INT DEFAULT 0,
    domain_age_days INT DEFAULT 0,
    ip_reputation INT DEFAULT 0,
    composite_data JSONB
);

-- Reports Table
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    pdf_path VARCHAR(500),
    json_data JSONB,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
