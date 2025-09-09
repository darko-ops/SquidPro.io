-- New unified users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    stellar_address VARCHAR(56),
    master_api_key VARCHAR(64) UNIQUE, -- Single key for all roles
    roles TEXT[] DEFAULT ARRAY['buyer'], -- ['buyer', 'supplier', 'reviewer']
    created_at TIMESTAMP DEFAULT NOW()
);

-- Role-specific profiles
CREATE TABLE user_supplier_profile (
    user_id INTEGER REFERENCES users(id),
    business_name VARCHAR(255),
    verified BOOLEAN DEFAULT FALSE,
    package_count INTEGER DEFAULT 0
);

CREATE TABLE user_reviewer_profile (
    user_id INTEGER REFERENCES users(id), 
    reputation_level VARCHAR(20) DEFAULT 'novice',
    specializations TEXT[],
    total_reviews INTEGER DEFAULT 0,
    consensus_rate DECIMAL(3,2) DEFAULT 0
);

-- Unified balance table
CREATE TABLE user_balance (
    user_id INTEGER REFERENCES users(id) UNIQUE,
    total_balance_usd DECIMAL(10,6) DEFAULT 0,
    supplier_earnings DECIMAL(10,6) DEFAULT 0,
    reviewer_earnings DECIMAL(10,6) DEFAULT 0,
    agent_credits DECIMAL(10,6) DEFAULT 0
    );

-- Data packages/products
CREATE TABLE data_packages (
    id SERIAL PRIMARY KEY,
    supplier_id INTEGER REFERENCES suppliers(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    endpoint_url TEXT NOT NULL,
    price_per_query DECIMAL(10,6) DEFAULT 0.005,
    sample_data JSONB,
    schema_definition JSONB,
    rate_limit INTEGER DEFAULT 1000, -- queries per hour
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'pending_review')),
    tags TEXT[], -- array of tags for searching
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Package usage tracking
CREATE TABLE package_usage (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id),
    agent_id VARCHAR(255),
    query_count INTEGER DEFAULT 0,
    last_used TIMESTAMP DEFAULT NOW(),
    total_spent DECIMAL(10,6) DEFAULT 0
);

-- Balance tracking
CREATE TABLE balances (
    id SERIAL PRIMARY KEY,
    user_type VARCHAR(20) CHECK (user_type IN ('supplier', 'reviewer', 'squidpro')),
    user_id VARCHAR(255),
    balance_usd DECIMAL(10,6) DEFAULT 0,
    pending_payout_usd DECIMAL(10,6) DEFAULT 0,
    payout_threshold_usd DECIMAL(10,2) DEFAULT 25.00,
    UNIQUE(user_type, user_id)
);

-- Transaction log
CREATE TABLE payout_history (
    id SERIAL PRIMARY KEY,
    stellar_tx_hash VARCHAR(64),
    recipient_address VARCHAR(56),
    amount_usd DECIMAL(10,6),
    user_type VARCHAR(20),
    user_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Query/transaction history
CREATE TABLE query_history (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id),
    agent_id VARCHAR(255),
    query_params JSONB,
    response_size INTEGER,
    cost DECIMAL(10,6),
    trace_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Add these tables to your existing schema.sql

-- Review tasks - automatically generated or manually created
CREATE TABLE review_tasks (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id),
    task_type VARCHAR(50) CHECK (task_type IN ('accuracy', 'freshness', 'schema', 'consensus', 'spot_audit')),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'completed', 'expired')),
    required_reviews INTEGER DEFAULT 3, -- how many reviewers needed for consensus
    reward_pool_usd DECIMAL(10,6) DEFAULT 0.05, -- total payout for this task
    reference_query JSONB, -- the query to test (params, expected structure)
    expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '24 hours'),
    created_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(20) DEFAULT 'system' -- 'system' or 'manual'
);

-- Individual review submissions
CREATE TABLE review_submissions (
    id SERIAL PRIMARY KEY,
    task_id INTEGER REFERENCES review_tasks(id),
    reviewer_id INTEGER REFERENCES reviewers(id),
    quality_score INTEGER CHECK (quality_score BETWEEN 1 AND 10), -- 1=terrible, 10=perfect
    timeliness_score INTEGER CHECK (timeliness_score BETWEEN 1 AND 10),
    schema_compliance_score INTEGER CHECK (schema_compliance_score BETWEEN 1 AND 10),
    overall_rating INTEGER CHECK (overall_rating BETWEEN 1 AND 10),
    evidence JSONB, -- their test data, comparisons, notes
    findings TEXT, -- written assessment
    test_timestamp TIMESTAMP, -- when they ran their verification
    submitted_at TIMESTAMP DEFAULT NOW(),
    is_consensus BOOLEAN DEFAULT FALSE, -- true if this matches majority opinion
    payout_earned DECIMAL(10,6) DEFAULT 0
);

-- Package quality scores (aggregated from reviews)
CREATE TABLE package_quality_scores (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id) UNIQUE,
    avg_quality_score DECIMAL(3,2) DEFAULT 0,
    avg_timeliness_score DECIMAL(3,2) DEFAULT 0,
    avg_schema_score DECIMAL(3,2) DEFAULT 0,
    overall_rating DECIMAL(3,2) DEFAULT 0,
    total_reviews INTEGER DEFAULT 0,
    last_reviewed TIMESTAMP,
    quality_trend VARCHAR(20) DEFAULT 'stable', -- 'improving', 'declining', 'stable'
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Reviewer reputation and stats
CREATE TABLE reviewer_stats (
    id SERIAL PRIMARY KEY,
    reviewer_id INTEGER REFERENCES reviewers(id) UNIQUE,
    total_reviews INTEGER DEFAULT 0,
    consensus_rate DECIMAL(3,2) DEFAULT 0, -- % of time they agree with majority
    accuracy_score DECIMAL(3,2) DEFAULT 0, -- how often their assessments prove correct
    total_earned DECIMAL(10,6) DEFAULT 0,
    avg_review_time_minutes INTEGER DEFAULT 0,
    specializations TEXT[], -- categories they're good at
    reputation_level VARCHAR(20) DEFAULT 'novice', -- 'novice', 'experienced', 'expert', 'master'
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Reviewer disputes (when reviewers disagree significantly)
CREATE TABLE review_disputes (
    id SERIAL PRIMARY KEY,
    task_id INTEGER REFERENCES review_tasks(id),
    dispute_reason TEXT,
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'escalated')),
    resolution_notes TEXT,
    resolved_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP
);

-- Add reputation level to existing reviewers table
ALTER TABLE reviewers ADD COLUMN IF NOT EXISTS reputation_level VARCHAR(20) DEFAULT 'novice';
ALTER TABLE reviewers ADD COLUMN IF NOT EXISTS specializations TEXT[];
ALTER TABLE reviewers ADD COLUMN IF NOT EXISTS api_key VARCHAR(64);

-- Insert some demo review tasks
INSERT INTO review_tasks (package_id, task_type, reward_pool_usd, reference_query) VALUES 
(1, 'accuracy', 0.05, '{"endpoint": "/price", "params": {"pair": "BTCUSDT"}, "expected_fields": ["price", "volume", "ts"]}'),
(1, 'freshness', 0.03, '{"endpoint": "/price", "params": {"pair": "ETHUSDT"}, "max_age_seconds": 30}'),
(1, 'schema', 0.02, '{"endpoint": "/price", "params": {"pair": "ADAUSDT"}, "schema_check": true}');

-- Initialize quality scores for existing packages
INSERT INTO package_quality_scores (package_id) 
SELECT id FROM data_packages ON CONFLICT (package_id) DO NOTHING;

-- Add index for performance
CREATE INDEX idx_review_tasks_status ON review_tasks(status);
CREATE INDEX idx_review_submissions_task ON review_submissions(task_id);
CREATE INDEX idx_package_quality_package ON package_quality_scores(package_id);


-- Insert demo suppliers and reviewers with Stellar addresses
INSERT INTO suppliers (name, stellar_address, email, api_key) VALUES 
('demo_supplier', 'GDXDSB444OLNDYOJAVGU3JWQO4BEGQT2MCVTDHLOWORRQODJJXO3GBDU', 'demo@cryptodata.io', 'sup_demo_12345'),
('crypto_data_co', 'GDXDSB444OLNDYOJAVGU3JWQO4BEGQT2MCVTDHLOWORRQODJJXO3GBDU', 'api@cryptodata.co', 'sup_crypto_67890');

INSERT INTO reviewers (name, stellar_address) VALUES
('demo_reviewer_pool', 'GAEAQRT27B2E7Y7VZYCHZA3VAVAC34JP7M3DLRAJF5LNCFDCWP74ECH2'),
('quality_auditor_1', 'GDXDSB444OLNDYOJAVGU3JWQO4BEGQT2MCVTDHLOWORRQODJJXO3GBDU');

-- Insert demo data packages
INSERT INTO data_packages (supplier_id, name, description, category, endpoint_url, price_per_query, sample_data, tags) VALUES 
(1, 'Crypto Price Feed', 'Real-time cryptocurrency prices with volume data', 'financial', 'http://collector-crypto:8200/price', 0.005, 
 '{"pair": "BTCUSDT", "price": 65000.50, "volume": 123.45, "ts": 1693123456}', 
 ARRAY['crypto', 'prices', 'real-time']),
 
(1, 'Market Sentiment Analysis', 'AI-powered sentiment analysis of crypto markets', 'financial', 'http://collector-crypto:8200/sentiment', 0.015,
 '{"symbol": "BTC", "sentiment": "bullish", "confidence": 0.85, "factors": ["social_media", "news"]}',
 ARRAY['sentiment', 'ai', 'analysis']),

(2, 'Weather Data Global', 'Current weather conditions for major cities worldwide', 'weather', 'http://weather-api:8300/current', 0.003,
 '{"city": "New York", "temp": 22.5, "humidity": 65, "conditions": "partly_cloudy"}',
 ARRAY['weather', 'global', 'current']);

-- Insert default balances with lower thresholds for demo
INSERT INTO balances (user_type, user_id, payout_threshold_usd) VALUES 
('squidpro', 'treasury', 100.00),
('supplier', '1', 0.02),  -- supplier ID instead of name
('supplier', '2', 0.02),
('reviewer', 'demo_reviewer_pool', 0.01);


-- Add to schema.sql
CREATE TABLE uploaded_datasets (
    id SERIAL PRIMARY KEY,
    supplier_id INTEGER REFERENCES suppliers(id),
    package_id INTEGER REFERENCES data_packages(id),
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER,
    file_hash VARCHAR(64),
    data_format VARCHAR(20), -- 'json', 'csv', 'parquet'
    row_count INTEGER,
    column_count INTEGER,
    schema_info JSONB,
    upload_date TIMESTAMP DEFAULT NOW(),
    last_accessed TIMESTAMP,
    access_count INTEGER DEFAULT 0
);

-- Add package_type to data_packages
ALTER TABLE data_packages ADD COLUMN package_type VARCHAR(20) DEFAULT 'api';
-- 'api' for external endpoints, 'upload' for uploaded datasets