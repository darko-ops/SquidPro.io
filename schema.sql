-- Complete SquidPro Database Schema

-- Core user tables
CREATE TABLE IF NOT EXISTS suppliers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    stellar_address VARCHAR(56),
    api_key VARCHAR(64) UNIQUE,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reviewers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    stellar_address VARCHAR(56),
    api_key VARCHAR(64) UNIQUE,
    reputation_level VARCHAR(20) DEFAULT 'novice',
    specializations TEXT[],
    created_at TIMESTAMP DEFAULT NOW()
);

-- Data packages
CREATE TABLE IF NOT EXISTS data_packages (
    id SERIAL PRIMARY KEY,
    supplier_id INTEGER REFERENCES suppliers(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    endpoint_url TEXT NOT NULL,
    price_per_query DECIMAL(10,6) DEFAULT 0.005,
    sample_data JSONB,
    schema_definition JSONB,
    rate_limit INTEGER DEFAULT 1000,
    status VARCHAR(20) DEFAULT 'active',
    tags TEXT[],
    package_type VARCHAR(20) DEFAULT 'api',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Balance tracking
CREATE TABLE IF NOT EXISTS balances (
    id SERIAL PRIMARY KEY,
    user_type VARCHAR(20) CHECK (user_type IN ('supplier', 'reviewer', 'squidpro')),
    user_id VARCHAR(255),
    balance_usd DECIMAL(10,6) DEFAULT 0,
    pending_payout_usd DECIMAL(10,6) DEFAULT 0,
    payout_threshold_usd DECIMAL(10,2) DEFAULT 25.00,
    UNIQUE(user_type, user_id)
);

-- Query/transaction history
CREATE TABLE IF NOT EXISTS query_history (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id),
    agent_id VARCHAR(255),
    query_params JSONB,
    response_size INTEGER,
    cost DECIMAL(10,6),
    trace_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Payout history
CREATE TABLE IF NOT EXISTS payout_history (
    id SERIAL PRIMARY KEY,
    stellar_tx_hash VARCHAR(64),
    recipient_address VARCHAR(56),
    amount_usd DECIMAL(10,6),
    user_type VARCHAR(20),
    user_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Review system tables
CREATE TABLE IF NOT EXISTS review_tasks (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id),
    task_type VARCHAR(50) CHECK (task_type IN ('accuracy', 'freshness', 'schema', 'consensus', 'spot_audit')),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'completed', 'expired')),
    required_reviews INTEGER DEFAULT 3,
    reward_pool_usd DECIMAL(10,6) DEFAULT 0.05,
    reference_query JSONB,
    expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '24 hours'),
    created_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(20) DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS review_submissions (
    id SERIAL PRIMARY KEY,
    task_id INTEGER REFERENCES review_tasks(id),
    reviewer_id INTEGER REFERENCES reviewers(id),
    quality_score INTEGER CHECK (quality_score BETWEEN 1 AND 10),
    timeliness_score INTEGER CHECK (timeliness_score BETWEEN 1 AND 10),
    schema_compliance_score INTEGER CHECK (schema_compliance_score BETWEEN 1 AND 10),
    overall_rating INTEGER CHECK (overall_rating BETWEEN 1 AND 10),
    evidence JSONB,
    findings TEXT,
    test_timestamp TIMESTAMP,
    submitted_at TIMESTAMP DEFAULT NOW(),
    is_consensus BOOLEAN DEFAULT FALSE,
    payout_earned DECIMAL(10,6) DEFAULT 0
);

CREATE TABLE IF NOT EXISTS package_quality_scores (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id) UNIQUE,
    avg_quality_score DECIMAL(3,2) DEFAULT 0,
    avg_timeliness_score DECIMAL(3,2) DEFAULT 0,
    avg_schema_score DECIMAL(3,2) DEFAULT 0,
    overall_rating DECIMAL(3,2) DEFAULT 0,
    total_reviews INTEGER DEFAULT 0,
    last_reviewed TIMESTAMP,
    quality_trend VARCHAR(20) DEFAULT 'stable',
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reviewer_stats (
    id SERIAL PRIMARY KEY,
    reviewer_id INTEGER REFERENCES reviewers(id) UNIQUE,
    total_reviews INTEGER DEFAULT 0,
    consensus_rate DECIMAL(3,2) DEFAULT 0,
    accuracy_score DECIMAL(3,2) DEFAULT 0,
    total_earned DECIMAL(10,6) DEFAULT 0,
    avg_review_time_minutes INTEGER DEFAULT 0,
    specializations TEXT[],
    reputation_level VARCHAR(20) DEFAULT 'novice',
    updated_at TIMESTAMP DEFAULT NOW()
);

-- File upload tables
CREATE TABLE IF NOT EXISTS uploaded_datasets (
    id SERIAL PRIMARY KEY,
    supplier_id INTEGER REFERENCES suppliers(id),
    package_id INTEGER REFERENCES data_packages(id),
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER,
    file_hash VARCHAR(64),
    data_format VARCHAR(20),
    row_count INTEGER,
    column_count INTEGER,
    schema_info JSONB,
    upload_date TIMESTAMP DEFAULT NOW(),
    last_accessed TIMESTAMP,
    access_count INTEGER DEFAULT 0
);

-- PII detection logs
CREATE TABLE IF NOT EXISTS pii_detection_log (
    id SERIAL PRIMARY KEY,
    supplier_id INTEGER REFERENCES suppliers(id),
    filename VARCHAR(255),
    pii_type VARCHAR(50),
    action_taken VARCHAR(20),
    findings_count INTEGER,
    blocked BOOLEAN,
    detection_details JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Unified user system (future)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    stellar_address VARCHAR(56),
    roles TEXT[] DEFAULT ARRAY['buyer'],
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_roles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    role_type VARCHAR(20),
    api_key VARCHAR(64),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_review_tasks_status ON review_tasks(status);
CREATE INDEX IF NOT EXISTS idx_review_submissions_task ON review_submissions(task_id);
CREATE INDEX IF NOT EXISTS idx_package_quality_package ON package_quality_scores(package_id);
CREATE INDEX IF NOT EXISTS idx_suppliers_api_key ON suppliers(api_key);
CREATE INDEX IF NOT EXISTS idx_reviewers_api_key ON reviewers(api_key);

-- Insert demo data
INSERT INTO suppliers (name, stellar_address, email, api_key) VALUES 
('Demo Crypto Data Provider', 'GDXDSB444OLNDYOJAVGU3JWQO4BEGQT2MCVTDHLOWORRQODJJXO3GBDU', 'demo@cryptodata.io', 'sup_demo_12345'),
('Alpha Financial Data', 'GDXDSB444OLNDYOJAVGU3JWQO4BEGQT2MCVTDHLOWORRQODJJXO3GBDU', 'api@alphafin.co', 'sup_crypto_67890')
ON CONFLICT (email) DO NOTHING;

INSERT INTO reviewers (name, stellar_address, email, api_key) VALUES
('Demo Quality Reviewer', 'GAEAQRT27B2E7Y7VZYCHZA3VAVAC34JP7M3DLRAJF5LNCFDCWP74ECH2', 'reviewer@demo.com', 'rev_demo_12345'),
('Data Quality Expert', 'GDXDSB444OLNDYOJAVGU3JWQO4BEGQT2MCVTDHLOWORRQODJJXO3GBDU', 'expert@quality.io', 'rev_expert_67890')
ON CONFLICT (email) DO NOTHING;

-- Insert demo packages
INSERT INTO data_packages (supplier_id, name, description, category, endpoint_url, price_per_query, sample_data, tags) VALUES 
(1, 'Real-time Crypto Prices', 'Live cryptocurrency price feed with volume data', 'financial', 'http://collector-crypto:8200/price', 0.005, 
 '{"pair": "BTCUSDT", "price": 65000.50, "volume": 123.45, "ts": 1693123456}', 
 ARRAY['crypto', 'prices', 'real-time']),
(1, 'Crypto Market Sentiment', 'AI-powered sentiment analysis of crypto markets', 'financial', 'http://collector-crypto:8200/price', 0.015,
 '{"symbol": "BTC", "sentiment": "bullish", "confidence": 0.85}',
 ARRAY['sentiment', 'ai', 'crypto'])
ON CONFLICT DO NOTHING;

-- Insert demo balances
INSERT INTO balances (user_type, user_id, payout_threshold_usd) VALUES 
('squidpro', 'treasury', 100.00),
('supplier', '1', 25.00),
('supplier', '2', 25.00),
('reviewer', '1', 5.00),
('reviewer', '2', 5.00)
ON CONFLICT (user_type, user_id) DO NOTHING;

-- Initialize quality scores for packages
INSERT INTO package_quality_scores (package_id) 
SELECT id FROM data_packages 
ON CONFLICT (package_id) DO NOTHING;

-- Insert reviewer stats
INSERT INTO reviewer_stats (reviewer_id) 
SELECT id FROM reviewers 
ON CONFLICT (reviewer_id) DO NOTHING;