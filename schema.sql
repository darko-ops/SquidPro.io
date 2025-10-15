-- Complete Obius Database Schema

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
    user_type VARCHAR(20) CHECK (user_type IN ('supplier', 'validator', 'obius', 'buyer')),
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
('obius', 'treasury', 100.00),
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



-- ============================================================================
-- VALIDATOR SYSTEM SCHEMA - Add to schema.sql
-- ============================================================================

-- Validation tasks (similar to review tasks but for infrastructure validation)
CREATE TABLE IF NOT EXISTS validation_tasks (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id),
    validation_type VARCHAR(50) CHECK (validation_type IN (
        'content_hash', 'schema', 'provenance', 'compliance', 'consensus'
    )),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'completed', 'expired')),
    required_validations INTEGER DEFAULT 3,
    reward_pool_usd DECIMAL(10,6) DEFAULT 0.10,
    reference_data JSONB,
    consensus_reached BOOLEAN DEFAULT FALSE,
    attestation JSONB,
    expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '48 hours'),
    created_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(20) DEFAULT 'system'
);

-- Validation submissions
CREATE TABLE IF NOT EXISTS validation_submissions (
    id SERIAL PRIMARY KEY,
    task_id INTEGER REFERENCES validation_tasks(id),
    validator_id INTEGER NOT NULL,  -- References users.id (unified auth)
    validation_type VARCHAR(50),
    passed BOOLEAN DEFAULT FALSE,
    confidence_score DECIMAL(3,2) CHECK (confidence_score BETWEEN 0 AND 1),
    validation_data JSONB,  -- Detailed validation results (hashes, schema checks, etc.)
    notes TEXT,
    submitted_at TIMESTAMP DEFAULT NOW(),
    is_consensus BOOLEAN DEFAULT FALSE,
    payout_earned DECIMAL(10,6) DEFAULT 0,
    UNIQUE(task_id, validator_id)  -- One submission per validator per task
);

-- Package validation scores (aggregate validation results)
CREATE TABLE IF NOT EXISTS package_validation_scores (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id) UNIQUE,
    consensus_score DECIMAL(3,2) DEFAULT 0,  -- Average confidence from validators
    validation_badges TEXT[],  -- e.g. ['content_hash_verified', 'schema_verified', 'compliance_verified']
    total_validations INTEGER DEFAULT 0,
    last_validated TIMESTAMP,
    hash_signature VARCHAR(64),  -- Latest dataset hash
    attestation_count INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Validator statistics (similar to reviewer_stats but for validators)
CREATE TABLE IF NOT EXISTS validator_stats (
    id SERIAL PRIMARY KEY,
    validator_id INTEGER UNIQUE NOT NULL,
    total_validations INTEGER DEFAULT 0,
    consensus_rate DECIMAL(3,2) DEFAULT 0,
    avg_confidence DECIMAL(3,2) DEFAULT 0,
    total_earned DECIMAL(10,6) DEFAULT 0,
    specializations TEXT[],
    reputation_level VARCHAR(30) DEFAULT 'novice_validator',
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Validation attestations (immutable record of validation proofs)
CREATE TABLE IF NOT EXISTS validation_attestations (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id),
    attestation_hash VARCHAR(64) UNIQUE,  -- SHA-256 of attestation data
    attestation_data JSONB,  -- Full attestation with signatures
    validator_count INTEGER,
    consensus_reached BOOLEAN,
    created_at TIMESTAMP DEFAULT NOW(),
    blockchain_tx_hash VARCHAR(64)  -- Future: Stellar transaction hash for on-chain attestation
);

-- Hash registry (track all dataset hashes for integrity verification)
CREATE TABLE IF NOT EXISTS dataset_hash_registry (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES data_packages(id),
    full_hash VARCHAR(64),
    chunk_hashes JSONB,
    row_count INTEGER,
    validated_at TIMESTAMP DEFAULT NOW(),
    validator_id INTEGER,  -- Who validated this hash
    is_current BOOLEAN DEFAULT TRUE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_validation_tasks_status ON validation_tasks(status);
CREATE INDEX IF NOT EXISTS idx_validation_tasks_package ON validation_tasks(package_id);
CREATE INDEX IF NOT EXISTS idx_validation_submissions_task ON validation_submissions(task_id);
CREATE INDEX IF NOT EXISTS idx_validation_submissions_validator ON validation_submissions(validator_id);
CREATE INDEX IF NOT EXISTS idx_package_validation_scores_package ON package_validation_scores(package_id);
CREATE INDEX IF NOT EXISTS idx_validator_stats_validator ON validator_stats(validator_id);
CREATE INDEX IF NOT EXISTS idx_validation_attestations_package ON validation_attestations(package_id);
CREATE INDEX IF NOT EXISTS idx_dataset_hash_registry_package ON dataset_hash_registry(package_id);

-- Initialize validation scores for existing packages
INSERT INTO package_validation_scores (package_id) 
SELECT id FROM data_packages 
ON CONFLICT (package_id) DO NOTHING;

-- Function to automatically create validation tasks when packages are uploaded
CREATE OR REPLACE FUNCTION create_validation_tasks_on_upload()
RETURNS TRIGGER AS $$
BEGIN
    -- Create content hash validation task
    INSERT INTO validation_tasks (package_id, validation_type, required_validations, reward_pool_usd)
    VALUES (NEW.id, 'content_hash', 3, 0.10);
    
    -- Create schema validation task
    INSERT INTO validation_tasks (package_id, validation_type, required_validations, reward_pool_usd)
    VALUES (NEW.id, 'schema', 3, 0.08);
    
    -- Create compliance validation task
    INSERT INTO validation_tasks (package_id, validation_type, required_validations, reward_pool_usd)
    VALUES (NEW.id, 'compliance', 3, 0.12);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-create validation tasks
CREATE TRIGGER auto_create_validation_tasks
AFTER INSERT ON data_packages
FOR EACH ROW
WHEN (NEW.package_type = 'upload')
EXECUTE FUNCTION create_validation_tasks_on_upload();

-- Sample validation tasks for demo packages
INSERT INTO validation_tasks (package_id, validation_type, required_validations, reward_pool_usd, reference_data)
SELECT 
    id,
    'content_hash',
    3,
    0.10,
    jsonb_build_object(
        'package_id', id,
        'package_name', name,
        'category', category,
        'created_at', NOW()::text
    )
FROM data_packages
WHERE package_type = 'upload'
ON CONFLICT DO NOTHING;

-- Initialize validator stats for users with validator role
INSERT INTO validator_stats (validator_id, total_validations, consensus_rate, avg_confidence, total_earned, reputation_level)
SELECT DISTINCT user_id, 0, 0, 0, 0, 'novice_validator'
FROM user_roles 
WHERE role_type = 'validator' AND is_active = TRUE
ON CONFLICT (validator_id) DO NOTHING;

-- Add validator balances
INSERT INTO balances (user_type, user_id, balance_usd, payout_threshold_usd)
SELECT 'validator', user_id::text, 0.00, 5.00
FROM user_roles
WHERE role_type = 'validator' AND is_active = TRUE
ON CONFLICT (user_type, user_id) DO NOTHING;

-- 3. Create sample validation tasks for existing packages
INSERT INTO validation_tasks (package_id, validation_type, required_validations, reward_pool_usd, reference_data, status, expires_at)
SELECT 
    dp.id,
    'content_hash',
    3,
    0.10,
    jsonb_build_object(
        'package_id', dp.id,
        'package_name', dp.name,
        'category', dp.category,
        'endpoint_url', dp.endpoint_url,
        'created_at', NOW()::text
    ),
    'open',
    NOW() + INTERVAL '48 hours'
FROM data_packages dp
WHERE NOT EXISTS (
    SELECT 1 FROM validation_tasks vt 
    WHERE vt.package_id = dp.id 
    AND vt.validation_type = 'content_hash'
    AND vt.status = 'open'
)
LIMIT 5;

-- 4. Create schema validation tasks
INSERT INTO validation_tasks (package_id, validation_type, required_validations, reward_pool_usd, reference_data, status, expires_at)
SELECT 
    dp.id,
    'schema',
    3,
    0.08,
    jsonb_build_object(
        'package_id', dp.id,
        'package_name', dp.name,
        'category', dp.category
    ),
    'open',
    NOW() + INTERVAL '48 hours'
FROM data_packages dp
WHERE NOT EXISTS (
    SELECT 1 FROM validation_tasks vt 
    WHERE vt.package_id = dp.id 
    AND vt.validation_type = 'schema'
    AND vt.status = 'open'
)
LIMIT 5;

-- 5. Create compliance validation tasks
INSERT INTO validation_tasks (package_id, validation_type, required_validations, reward_pool_usd, reference_data, status, expires_at)
SELECT 
    dp.id,
    'compliance',
    3,
    0.12,
    jsonb_build_object(
        'package_id', dp.id,
        'package_name', dp.name,
        'category', dp.category
    ),
    'open',
    NOW() + INTERVAL '48 hours'
FROM data_packages dp
WHERE NOT EXISTS (
    SELECT 1 FROM validation_tasks vt 
    WHERE vt.package_id = dp.id 
    AND vt.validation_type = 'compliance'
    AND vt.status = 'open'
)
LIMIT 5;

-- 6. Initialize package validation scores
INSERT INTO package_validation_scores (package_id, consensus_score, total_validations)
SELECT id, 0, 0
FROM data_packages
ON CONFLICT (package_id) DO NOTHING;

-- 7. Verify setup
SELECT 
    'Users with Validator Role' as check_name,
    COUNT(*) as count
FROM user_roles
WHERE role_type = 'validator' AND is_active = TRUE

UNION ALL

SELECT 
    'Validator Stats Initialized',
    COUNT(*)
FROM validator_stats

UNION ALL

SELECT 
    'Validator Balances',
    COUNT(*)
FROM balances
WHERE user_type = 'validator'

UNION ALL

SELECT 
    'Open Validation Tasks',
    COUNT(*)
FROM validation_tasks
WHERE status = 'open' AND expires_at > NOW();

-- 8. Show available tasks
SELECT 
    vt.id as task_id,
    dp.name as package_name,
    dp.category,
    s.name as supplier_name,
    vt.validation_type,
    vt.reward_pool_usd,
    vt.required_validations,
    COALESCE(submission_count.count, 0) as current_submissions,
    (vt.required_validations - COALESCE(submission_count.count, 0)) as spots_remaining,
    vt.expires_at
FROM validation_tasks vt
JOIN data_packages dp ON vt.package_id = dp.id
JOIN suppliers s ON dp.supplier_id = s.id
LEFT JOIN (
    SELECT task_id, COUNT(*) as count 
    FROM validation_submissions 
    GROUP BY task_id
) submission_count ON vt.id = submission_count.task_id
WHERE vt.status = 'open' 
AND vt.expires_at > NOW()
ORDER BY vt.created_at DESC
LIMIT 10;

-- 9. Show validator info for debugging
SELECT 
    u.id,
    u.name,
    u.email,
    ur.role_type,
    ur.api_key,
    vs.total_validations,
    vs.reputation_level,
    b.balance_usd
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN validator_stats vs ON u.id = vs.validator_id
LEFT JOIN balances b ON u.id::text = b.user_id AND b.user_type = 'validator'
WHERE ur.role_type = 'validator' AND ur.is_active = TRUE
LIMIT 10;