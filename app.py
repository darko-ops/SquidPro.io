import os, time, uuid, jwt, httpx, asyncpg, json
import hashlib, re, asyncio, logging, secrets, statistics
from datetime import datetime, timedelta
from enum import Enum
from decimal import Decimal
from io import StringIO
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any, Tuple

from fastapi import FastAPI, Header, HTTPException, Query, File, UploadFile, Form
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, validator

from stellar_sdk import Keypair, Network, Server, TransactionBuilder, Asset
from stellar_sdk.exceptions import SdkError

import pandas as pd
import bcrypt

# Create uploads directory
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
logging.basicConfig(level=logging.INFO)

# Configuration
SECRET = os.getenv("OBIUS_SECRET", "supersecret_change_me")
PRICE = float(os.getenv("PRICE_PER_QUERY_USD", "0.005"))
SPLIT_SUPPLIER = float(os.getenv("SUPPLIER_SPLIT", "0.7"))
SPLIT_REVIEWER = float(os.getenv("REVIEWER_SPLIT", "0.2"))
SPLIT_OBIUS = float(os.getenv("OBIUS_SPLIT", "0.1"))
COLLECTOR = os.getenv("COLLECTOR_CRYPTO_URL", "http://collector-crypto:8200")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://obius:password@postgres:5432/obius")

# Stellar configuration
STELLAR_SECRET_KEY = os.getenv("STELLAR_SECRET_KEY", "SAMPLEKEY123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890AB")
STELLAR_NETWORK = os.getenv("STELLAR_NETWORK", "testnet")
USDC_ASSET_CODE = os.getenv("USDC_ASSET_CODE", "USDC")
USDC_ASSET_ISSUER = os.getenv("USDC_ASSET_ISSUER", "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5")

# Stellar setup
try:
    stellar_keypair = Keypair.from_secret(STELLAR_SECRET_KEY)
    stellar_server = Server("https://horizon-testnet.stellar.org") if STELLAR_NETWORK == "testnet" else Server("https://horizon.stellar.org")
    usdc_asset = Asset(USDC_ASSET_CODE, USDC_ASSET_ISSUER)
    logging.info(f"Stellar initialized - Public Key: {stellar_keypair.public_key}")
except Exception as e:
    logging.error(f"Failed to initialize Stellar: {e}")
    stellar_keypair = None

# Global variables
db_pool = None
active_sessions = {}

# Enums
class PIIType(Enum):
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    USERNAME = "username"
    PASSWORD = "password"

class PIIAction(Enum):
    BLOCK = "block"
    REDACT = "redact"
    MASK = "mask"
    LOG_ONLY = "log_only"

# Pydantic Models
class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    name: str = Field(..., min_length=1, max_length=255)
    email: str = Field(..., pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    password: str = Field(..., min_length=8, max_length=128)
    repeat_password: str
    stellar_address: str = Field(..., min_length=56, max_length=56)
    roles: List[str] = Field(..., min_items=1)  # ['supplier', 'buyer', 'reviewer']
    
    @validator('repeat_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('roles')
    def validate_roles(cls, v):
        valid_roles = {'supplier', 'buyer', 'validator'}
        for role in v:
            if role not in valid_roles:
                raise ValueError(f'Invalid role: {role}')
        return v

class LoginCredentials(BaseModel):
    username: str
    password: str

class UserSession(BaseModel):
    user_id: int
    username: str
    name: str
    email: str
    roles: List[str]
    api_key: str
    stellar_address: str

class MintReq(BaseModel):
    agent_id: str
    scope: str = "data.read.price"
    credits: float = Field(..., ge=0.001, le=1000.0)

class ReviewerRegistration(BaseModel):
    name: str
    stellar_address: str
    email: Optional[str] = None
    specializations: List[str] = []

class ReviewSubmission(BaseModel):
    quality_score: int
    timeliness_score: int
    schema_compliance_score: int
    overall_rating: int
    findings: str
    evidence: Optional[Dict[str, Any]] = None

class SupplierRegistration(BaseModel):
    name: str
    email: str
    stellar_address: str

class DataPackage(BaseModel):
    name: str
    description: str
    category: str
    endpoint_url: str
    price_per_query: float = 0.005
    sample_data: Optional[Dict[str, Any]] = None
    schema_definition: Optional[Dict[str, Any]] = None
    rate_limit: int = 1000
    tags: List[str] = []

class DatasetUpload(BaseModel):
    name: str
    description: str
    category: str
    price_per_query: float = 0.005
    tags: List[str] = []
    data_format: str
    update_frequency: str = 'static'
    sample_size: int = 10

# PII Detection Configuration
PII_PATTERNS = {
    PIIType.EMAIL: {
        'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'description': 'Email addresses',
        'action': PIIAction.BLOCK
    },
    PIIType.PHONE: {
        'pattern': r'(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})',
        'description': 'Phone numbers',
        'action': PIIAction.MASK
    },
    PIIType.SSN: {
        'pattern': r'\b\d{3}-?\d{2}-?\d{4}\b',
        'description': 'Social Security Numbers',
        'action': PIIAction.BLOCK
    },
    PIIType.CREDIT_CARD: {
        'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        'description': 'Credit card numbers',
        'action': PIIAction.BLOCK
    },
    PIIType.IP_ADDRESS: {
        'pattern': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'description': 'IP addresses',
        'action': PIIAction.LOG_ONLY
    },
    PIIType.USERNAME: {
        'pattern': r'\b(?:user|username|login|account)[:=]\s*([A-Za-z0-9_.-]+)\b',
        'description': 'Username/login credentials',
        'action': PIIAction.REDACT
    },
    PIIType.PASSWORD: {
        'pattern': r'\b(?:pass|password|pwd)[:=]\s*([^\s,;|]+)\b',
        'description': 'Passwords',
        'action': PIIAction.BLOCK
    }
}


# Validation Types
class ValidationType:
    CONTENT_HASH = "content_hash"
    SCHEMA = "schema"
    PROVENANCE = "provenance"
    COMPLIANCE = "compliance"
    CONSENSUS = "consensus"

# Validator Actions
async def create_validation_task(conn, package_id: int, validation_type: str, reward_pool: float = 0.10):
    """Create a validation task for a data package"""
    task_id = await conn.fetchval("""
        INSERT INTO validation_tasks (
            package_id, 
            validation_type, 
            status,
            required_validations,
            reward_pool_usd,
            expires_at
        ) VALUES ($1, $2, 'open', 3, $3, NOW() + INTERVAL '48 hours')
        RETURNING id
    """, package_id, validation_type, reward_pool)
    
    # Get package metadata for reference
    package = await conn.fetchrow("""
        SELECT * FROM data_packages WHERE id = $1
    """, package_id)
    
    # Create reference data for validators
    reference_data = {
        "package_id": package_id,
        "package_name": package["name"],
        "endpoint_url": package["endpoint_url"],
        "package_type": package["package_type"],
        "category": package["category"],
        "created_at": package["created_at"].isoformat()
    }
    
    await conn.execute("""
        UPDATE validation_tasks 
        SET reference_data = $1
        WHERE id = $2
    """, json.dumps(reference_data), task_id)
    
    return task_id


# Hash Validation
def compute_dataset_hash(data: pd.DataFrame) -> Tuple[str, Dict[str, str]]:
    """Compute SHA-256 hash of dataset and chunk hashes"""
    # Full dataset hash
    dataset_bytes = data.to_csv(index=False).encode('utf-8')
    full_hash = hashlib.sha256(dataset_bytes).hexdigest()
    
    # Chunk hashes (by row batches)
    chunk_size = 1000
    chunk_hashes = {}
    
    for i in range(0, len(data), chunk_size):
        chunk = data.iloc[i:i+chunk_size]
        chunk_bytes = chunk.to_csv(index=False).encode('utf-8')
        chunk_hash = hashlib.sha256(chunk_bytes).hexdigest()
        chunk_hashes[f"chunk_{i//chunk_size}"] = chunk_hash
    
    return full_hash, chunk_hashes

async def validate_content_hash(file_path: str, stored_hash: Optional[str] = None) -> Dict:
    """Validate content integrity via hashing"""
    try:
        df = pd.read_csv(file_path)
        
        # Compute hashes
        full_hash, chunk_hashes = compute_dataset_hash(df)
        
        # Compare with stored hash if provided
        hash_match = True
        if stored_hash:
            hash_match = (full_hash == stored_hash)
        
        return {
            "validation_type": "content_hash",
            "passed": hash_match,
            "full_hash": full_hash,
            "chunk_count": len(chunk_hashes),
            "chunk_hashes": chunk_hashes,
            "row_count": len(df),
            "timestamp": datetime.now().isoformat(),
            "details": "Dataset integrity verified" if hash_match else "Hash mismatch detected"
        }
    except Exception as e:
        return {
            "validation_type": "content_hash",
            "passed": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# Schema Validation
async def validate_schema(file_path: str, declared_schema: Optional[Dict] = None) -> Dict:
    """Validate data conforms to declared schema"""
    try:
        df = pd.read_csv(file_path)
        
        # Extract actual schema
        actual_schema = {
            col: str(df[col].dtype) for col in df.columns
        }
        
        # Check for nulls
        null_counts = df.isnull().sum().to_dict()
        
        # Check data types consistency
        type_issues = []
        for col in df.columns:
            # Check if column has mixed types
            if df[col].dtype == 'object':
                try:
                    pd.to_numeric(df[col])
                    type_issues.append(f"{col}: appears numeric but stored as object")
                except:
                    pass
        
        # Compare with declared schema if provided
        schema_match = True
        schema_differences = []
        
        if declared_schema:
            for col, expected_type in declared_schema.items():
                if col not in actual_schema:
                    schema_match = False
                    schema_differences.append(f"Missing column: {col}")
                elif actual_schema[col] != expected_type:
                    schema_match = False
                    schema_differences.append(
                        f"Type mismatch for {col}: expected {expected_type}, got {actual_schema[col]}"
                    )
        
        passed = schema_match and len(type_issues) == 0
        
        return {
            "validation_type": "schema",
            "passed": passed,
            "actual_schema": actual_schema,
            "null_counts": null_counts,
            "type_issues": type_issues,
            "schema_differences": schema_differences,
            "column_count": len(df.columns),
            "row_count": len(df),
            "timestamp": datetime.now().isoformat(),
            "details": "Schema validation passed" if passed else "Schema issues detected"
        }
    except Exception as e:
        return {
            "validation_type": "schema",
            "passed": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# Provenance Validation
async def validate_provenance(package_id: int, conn) -> Dict:
    """Check provenance - how data was obtained"""
    try:
        # Get package metadata
        package = await conn.fetchrow("""
            SELECT * FROM data_packages WHERE id = $1
        """, package_id)
        
        # Check if uploaded dataset
        upload_info = await conn.fetchrow("""
            SELECT * FROM uploaded_datasets WHERE package_id = $1
        """, package_id)
        
        provenance_data = {
            "package_type": package["package_type"],
            "created_at": package["created_at"].isoformat(),
            "supplier_id": package["supplier_id"]
        }
        
        if upload_info:
            provenance_data.update({
                "upload_date": upload_info["upload_date"].isoformat(),
                "file_hash": upload_info["file_hash"],
                "original_filename": upload_info["original_filename"],
                "data_format": upload_info["data_format"]
            })
        
        # Check access history
        access_count = await conn.fetchval("""
            SELECT COUNT(*) FROM query_history WHERE package_id = $1
        """, package_id)
        
        provenance_data["access_count"] = access_count
        
        # Check PII logs
        pii_logs = await conn.fetch("""
            SELECT pii_type, action_taken, findings_count
            FROM pii_detection_log
            WHERE filename IN (
                SELECT filename FROM uploaded_datasets WHERE package_id = $1
            )
        """, package_id)
        
        provenance_data["pii_checks"] = [
            {
                "type": log["pii_type"],
                "action": log["action_taken"],
                "findings": log["findings_count"]
            }
            for log in pii_logs
        ]
        
        passed = True  # Provenance exists and is traceable
        
        return {
            "validation_type": "provenance",
            "passed": passed,
            "provenance_data": provenance_data,
            "timestamp": datetime.now().isoformat(),
            "details": "Provenance chain verified"
        }
    except Exception as e:
        return {
            "validation_type": "provenance",
            "passed": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# Compliance Validation
async def validate_compliance(file_path: str, package_category: str) -> Dict:
    """Check compliance - PII, ToS, robots.txt"""
    try:
        df = pd.read_csv(file_path)
        
        # Re-run PII detection
        from app import PIIDetector
        detector = PIIDetector()
        pii_analysis = detector.scan_dataframe(df)
        
        compliance_issues = []
        
        # Check for blocking PII issues
        if pii_analysis['blocking_issues']:
            compliance_issues.append({
                "type": "pii_violation",
                "severity": "critical",
                "count": len(pii_analysis['blocking_issues']),
                "details": "Blocking PII detected in dataset"
            })
        
        # Check for category-specific compliance
        if package_category == 'financial':
            # Financial data should not have personal identifiers
            if 'email' in pii_analysis['findings_by_type']:
                compliance_issues.append({
                    "type": "financial_pii",
                    "severity": "high",
                    "details": "Email addresses in financial dataset"
                })
        
        passed = len([issue for issue in compliance_issues if issue['severity'] == 'critical']) == 0
        
        return {
            "validation_type": "compliance",
            "passed": passed,
            "pii_findings": pii_analysis['findings_by_type'],
            "compliance_issues": compliance_issues,
            "total_issues": len(compliance_issues),
            "timestamp": datetime.now().isoformat(),
            "details": "Compliance verified" if passed else "Compliance violations detected"
        }
    except Exception as e:
        return {
            "validation_type": "compliance",
            "passed": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# Consensus Processing
async def process_validation_consensus(conn, task_id: int):
    """Process consensus when enough validations are submitted"""
    submissions = await conn.fetch("""
        SELECT * FROM validation_submissions WHERE task_id = $1
    """, task_id)
    
    if len(submissions) < 3:  # Need at least 3 validators
        return
    
    # Analyze consensus
    passed_count = sum(1 for s in submissions if s["passed"])
    consensus_reached = passed_count >= 2  # Majority rule
    
    # Calculate average confidence
    avg_confidence = sum(s["confidence_score"] for s in submissions) / len(submissions)
    
    # Aggregate findings
    all_findings = {}
    for sub in submissions:
        validation_data = sub["validation_data"]
        if validation_data:
            for key, value in validation_data.items():
                if key not in all_findings:
                    all_findings[key] = []
                all_findings[key].append(value)
    
    # Calculate payouts
    task = await conn.fetchrow("SELECT * FROM validation_tasks WHERE id = $1", task_id)
    reward_per_validator = float(task["reward_pool_usd"]) / len(submissions)
    
    for submission in submissions:
        # Bonus for consensus
        contributed_to_consensus = submission["passed"] == consensus_reached
        payout = reward_per_validator * (1.3 if contributed_to_consensus else 0.7)
        
        await conn.execute("""
            UPDATE validation_submissions 
            SET is_consensus = $1, payout_earned = $2
            WHERE id = $3
        """, contributed_to_consensus, payout, submission["id"])
        
        # Update validator balance
        await conn.execute("""
            INSERT INTO balances (user_type, user_id, balance_usd)
            VALUES ('validator', $1, $2)
            ON CONFLICT (user_type, user_id)
            DO UPDATE SET balance_usd = balances.balance_usd + $2
        """, str(submission["validator_id"]), payout)
    
    # Update package validation status
    await update_package_validation_status(conn, task["package_id"], submissions, consensus_reached)
    
    # Generate attestation
    attestation = generate_validation_attestation(task, submissions, consensus_reached, all_findings)
    
    await conn.execute("""
        UPDATE validation_tasks 
        SET status = 'completed', 
            consensus_reached = $1,
            attestation = $2
        WHERE id = $3
    """, consensus_reached, json.dumps(attestation), task_id)
    
    # Update validator stats
    for submission in submissions:
        await update_validator_stats(conn, submission["validator_id"])

async def update_package_validation_status(conn, package_id: int, submissions: list, consensus_reached: bool):
    """Update package validation scores"""
    # Calculate aggregate scores
    avg_confidence = sum(s["confidence_score"] for s in submissions) / len(submissions)
    
    validation_badges = []
    if consensus_reached:
        validation_badges.append("consensus_verified")
    
    # Check which validations passed
    validation_types = set(s["validation_type"] for s in submissions)
    for vtype in validation_types:
        type_submissions = [s for s in submissions if s["validation_type"] == vtype]
        if sum(1 for s in type_submissions if s["passed"]) >= len(type_submissions) * 0.66:
            validation_badges.append(f"{vtype}_verified")
    
    await conn.execute("""
        INSERT INTO package_validation_scores (
            package_id, 
            consensus_score, 
            validation_badges,
            total_validations,
            last_validated
        ) VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (package_id) 
        DO UPDATE SET 
            consensus_score = $2,
            validation_badges = $3,
            total_validations = package_validation_scores.total_validations + $4,
            last_validated = NOW()
    """, package_id, avg_confidence, validation_badges, len(submissions))

def generate_validation_attestation(task, submissions, consensus_reached, findings):
    """Generate cryptographic attestation of validation"""
    attestation = {
        "task_id": task["id"],
        "package_id": task["package_id"],
        "validation_type": task["validation_type"],
        "timestamp": datetime.now().isoformat(),
        "consensus_reached": consensus_reached,
        "validator_count": len(submissions),
        "findings": findings,
        "signatures": []
    }
    
    # Generate attestation hash
    attestation_string = json.dumps(attestation, sort_keys=True)
    attestation["attestation_hash"] = hashlib.sha256(attestation_string.encode()).hexdigest()
    
    # Add validator signatures (simulated - would use actual crypto signatures in production)
    for sub in submissions:
        signature = hashlib.sha256(
            f"{sub['validator_id']}{attestation['attestation_hash']}".encode()
        ).hexdigest()
        
        attestation["signatures"].append({
            "validator_id": sub["validator_id"],
            "signature": signature,
            "passed": sub["passed"],
            "confidence": sub["confidence_score"]
        })
    
    return attestation

async def update_validator_stats(conn, validator_id: int):
    """Update validator statistics"""
    stats = await conn.fetchrow("""
        SELECT 
            COUNT(*) as total_validations,
            AVG(CASE WHEN is_consensus THEN 1.0 ELSE 0.0 END) as consensus_rate,
            AVG(confidence_score) as avg_confidence,
            SUM(payout_earned) as total_earned
        FROM validation_submissions 
        WHERE validator_id = $1
    """, validator_id)
    
    # Calculate reputation level
    total = stats["total_validations"]
    consensus_rate = float(stats["consensus_rate"] or 0)
    
    if total >= 100 and consensus_rate >= 0.9:
        reputation = "master_validator"
    elif total >= 50 and consensus_rate >= 0.85:
        reputation = "expert_validator"
    elif total >= 20 and consensus_rate >= 0.75:
        reputation = "experienced_validator"
    else:
        reputation = "novice_validator"
    
    await conn.execute("""
        INSERT INTO validator_stats (
            validator_id,
            total_validations,
            consensus_rate,
            avg_confidence,
            total_earned,
            reputation_level
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (validator_id)
        DO UPDATE SET
            total_validations = $2,
            consensus_rate = $3,
            avg_confidence = $4,
            total_earned = $5,
            reputation_level = $6,
            updated_at = NOW()
    """, validator_id, total, stats["consensus_rate"], 
    stats["avg_confidence"], stats["total_earned"], reputation)

# Helper Functions
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_session_token() -> str:
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def _auth(auth_header: Optional[str]):
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = auth_header.split(" ", 1)[1]
    try:
        claims = jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    return claims

async def update_balances(supplier_amt: float, reviewer_pool: float, obius_amt: float, supplier_id: str = "1"):
    """Update balances for supplier, reviewer pool, and obius treasury"""
    async with db_pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO balances (user_type, user_id, balance_usd) 
            VALUES ('supplier', $1, $2)
            ON CONFLICT (user_type, user_id) 
            DO UPDATE SET balance_usd = balances.balance_usd + $2
        """, supplier_id, supplier_amt)
        
        await conn.execute("""
            INSERT INTO balances (user_type, user_id, balance_usd) 
            VALUES ('reviewer', 'demo_reviewer_pool', $1)
            ON CONFLICT (user_type, user_id) 
            DO UPDATE SET balance_usd = balances.balance_usd + $1
        """, reviewer_pool)
        
        await conn.execute("""
            INSERT INTO balances (user_type, user_id, balance_usd) 
            VALUES ('obius', 'treasury', $1)
            ON CONFLICT (user_type, user_id) 
            DO UPDATE SET balance_usd = balances.balance_usd + $1
        """, obius_amt)

async def log_pii_detection(conn, supplier_id: int, filename: str, analysis: Dict):
    """Log PII detection results to database"""
    for pii_type, count in analysis['findings_by_type'].items():
        action = 'block' if analysis['blocking_issues'] else 'allow'
        blocked = len(analysis['blocking_issues']) > 0
        
        await conn.execute("""
            INSERT INTO pii_detection_log 
            (supplier_id, filename, pii_type, action_taken, findings_count, blocked, detection_details)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        """, supplier_id, filename, pii_type, action, count, blocked, json.dumps(analysis))

async def authenticate_user_session(session_token: str) -> UserSession:
    """Authenticate user by session token"""
    if not session_token or session_token not in active_sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    session = active_sessions[session_token]
    
    if datetime.now() > session["expires_at"]:
        del active_sessions[session_token]
        raise HTTPException(status_code=401, detail="Session expired")
    
    return session["data"]
    
    async with db_pool.acquire() as conn:
        supplier = await conn.fetchrow("""
            SELECT id, name, status FROM suppliers WHERE api_key = $1 AND status = 'active'
        """, api_key)
        
        if not supplier:
            raise HTTPException(status_code=401, detail="Invalid or inactive supplier")
        
        return supplier

# REPLACE with this new unified function:
async def authenticate_unified_user(api_key: str, required_role: str = None):
    """Authenticate user by unified API key and optionally check role"""
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    if not api_key.startswith('usr_'):
        raise HTTPException(status_code=401, detail="Invalid API key format. Expected usr_ key.")
    
    async with db_pool.acquire() as conn:
        user_role = await conn.fetchrow("""
            SELECT ur.user_id, ur.role_type, ur.api_key, u.name, u.email, u.stellar_address
            FROM user_roles ur
            JOIN users u ON ur.user_id = u.id
            WHERE ur.api_key = $1 AND ur.is_active = TRUE
        """, api_key)
        
        if not user_role:
            raise HTTPException(status_code=401, detail="Invalid or inactive API key")
        
        all_roles = await conn.fetch("""
            SELECT role_type FROM user_roles WHERE user_id = $1 AND is_active = TRUE
        """, user_role["user_id"])
        
        roles = [role["role_type"] for role in all_roles]
        
        if required_role and required_role not in roles:
            raise HTTPException(status_code=403, detail=f"User does not have required role: {required_role}")
        
        return {
            "user_id": user_role["user_id"],
            "name": user_role["name"],
            "email": user_role["email"],
            "stellar_address": user_role["stellar_address"],
            "roles": roles,
            "api_key": user_role["api_key"]
        }
    
    async with db_pool.acquire() as conn:
        reviewer = await conn.fetchrow("""
            SELECT r.id, r.name, r.reputation_level, rs.consensus_rate, rs.accuracy_score
            FROM reviewers r
            LEFT JOIN reviewer_stats rs ON r.id = rs.reviewer_id
            WHERE r.api_key = $1
        """, api_key)
        
        if not reviewer:
            raise HTTPException(status_code=401, detail="Invalid reviewer API key")
        
        return reviewer

async def add_unique_constraints():
    """Add unique constraints to database tables"""
    async with db_pool.acquire() as conn:
        constraints = [
            "ALTER TABLE suppliers ADD CONSTRAINT IF NOT EXISTS suppliers_email_unique UNIQUE (email)",
            "ALTER TABLE suppliers ADD CONSTRAINT IF NOT EXISTS suppliers_name_unique UNIQUE (name)", 
            "ALTER TABLE suppliers ADD CONSTRAINT IF NOT EXISTS suppliers_stellar_address_unique UNIQUE (stellar_address)",
            "ALTER TABLE suppliers ADD CONSTRAINT IF NOT EXISTS suppliers_api_key_unique UNIQUE (api_key)",
            "ALTER TABLE reviewers ADD CONSTRAINT IF NOT EXISTS reviewers_email_unique UNIQUE (email)",
            "ALTER TABLE reviewers ADD CONSTRAINT IF NOT EXISTS reviewers_name_unique UNIQUE (name)",
            "ALTER TABLE reviewers ADD CONSTRAINT IF NOT EXISTS reviewers_stellar_address_unique UNIQUE (stellar_address)", 
            "ALTER TABLE reviewers ADD CONSTRAINT IF NOT EXISTS reviewers_api_key_unique UNIQUE (api_key)"
        ]
        
        for constraint_sql in constraints:
            try:
                await conn.execute(constraint_sql)
                print(f"✅ Applied constraint: {constraint_sql}")
            except Exception as e:
                if "already exists" in str(e):
                    print(f"⏭️ Constraint already exists: {constraint_sql}")
                else:
                    print(f"❌ Failed to apply constraint: {constraint_sql} - {e}")

# PII Detector Class
class PIIDetector:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or PII_PATTERNS
        self.detection_log = []
    
    def scan_text(self, text: str, context: str = "") -> List[Dict]:
        """Scan text for PII patterns"""
        findings = []
        
        for pii_type, pattern_config in self.config.items():
            pattern = pattern_config['pattern']
            matches = re.finditer(pattern, str(text), re.IGNORECASE)
            
            for match in matches:
                finding = {
                    'type': pii_type.value,
                    'pattern': pattern_config['description'],
                    'action': pattern_config['action'].value,
                    'match': match.group(),
                    'position': match.span(),
                    'context': context,
                    'confidence': self._calculate_confidence(pii_type, match.group())
                }
                findings.append(finding)
        
        return findings
    
    def scan_dataframe(self, df: pd.DataFrame) -> Dict:
        """Scan entire dataframe for PII"""
        all_findings = []
        
        for column in df.columns:
            for idx, value in df[column].items():
                if pd.notna(value):
                    findings = self.scan_text(str(value), f"Column: {column}, Row: {idx}")
                    all_findings.extend(findings)
        
        analysis = {
            'total_findings': len(all_findings),
            'findings_by_type': {},
            'findings_by_action': {},
            'blocking_issues': [],
            'all_findings': all_findings
        }
        
        for finding in all_findings:
            pii_type = finding['type']
            action = finding['action']
            
            if pii_type not in analysis['findings_by_type']:
                analysis['findings_by_type'][pii_type] = 0
            analysis['findings_by_type'][pii_type] += 1
            
            if action not in analysis['findings_by_action']:
                analysis['findings_by_action'][action] = 0
            analysis['findings_by_action'][action] += 1
            
            if action == PIIAction.BLOCK.value:
                analysis['blocking_issues'].append(finding)
        
        return analysis
    
    def clean_dataframe(self, df: pd.DataFrame, analysis: Dict) -> Tuple[pd.DataFrame, Dict]:
        """Clean dataframe based on PII findings"""
        cleaned_df = df.copy()
        cleaning_log = []
        
        for finding in analysis['all_findings']:
            action = finding['action']
            
            if action == PIIAction.REDACT.value:
                column, row = self._parse_context(finding['context'])
                if column and row is not None:
                    original_value = str(cleaned_df.loc[row, column])
                    cleaned_value = re.sub(re.escape(finding['match']), '[REDACTED]', original_value)
                    cleaned_df.loc[row, column] = cleaned_value
                    cleaning_log.append(f"Redacted {finding['type']} in {column}, row {row}")
            
            elif action == PIIAction.MASK.value:
                column, row = self._parse_context(finding['context'])
                if column and row is not None:
                    original_value = str(cleaned_df.loc[row, column])
                    masked_value = self._mask_value(finding['match'], finding['type'])
                    cleaned_value = original_value.replace(finding['match'], masked_value)
                    cleaned_df.loc[row, column] = cleaned_value
                    cleaning_log.append(f"Masked {finding['type']} in {column}, row {row}")
        
        return cleaned_df, {'actions_taken': cleaning_log}
    
    def _calculate_confidence(self, pii_type: PIIType, match: str) -> float:
        """Calculate confidence score for PII detection"""
        if pii_type == PIIType.EMAIL:
            return 0.95 if '@' in match and '.' in match else 0.7
        elif pii_type == PIIType.SSN:
            return 0.9 if '-' in match else 0.8
        elif pii_type == PIIType.PHONE:
            return 0.85 if len(re.sub(r'[^\d]', '', match)) == 10 else 0.7
        else:
            return 0.8
    
    def _parse_context(self, context: str) -> Tuple[Optional[str], Optional[int]]:
        """Parse context string to extract column and row"""
        try:
            parts = context.split(', ')
            column = parts[0].replace('Column: ', '') if len(parts) > 0 else None
            row = int(parts[1].replace('Row: ', '')) if len(parts) > 1 else None
            return column, row
        except:
            return None, None
    
    def _mask_value(self, value: str, pii_type: str) -> str:
        """Apply masking to PII values"""
        if pii_type == 'phone':
            digits = re.sub(r'[^\d]', '', value)
            if len(digits) == 10:
                return f"({digits[:3]}) ***-{digits[-4:]}"
        elif pii_type == 'ssn':
            digits = re.sub(r'[^\d]', '', value)
            if len(digits) == 9:
                return f"***-**-{digits[-4:]}"
        
        return '*' * (len(value) - 4) + value[-4:] if len(value) > 4 else '****'

# Stellar Payment Functions
async def send_stellar_payment(recipient_address: str, amount_usd: float) -> str:
    """Send XLM payment via Stellar and return transaction hash"""
    if not stellar_keypair:
        raise Exception("Stellar not properly initialized")
    
    try:
        source_account = stellar_server.load_account(stellar_keypair.public_key)
        
        transaction = (
            TransactionBuilder(
                source_account=source_account,
                network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE if STELLAR_NETWORK == "testnet" else Network.PUBLIC_NETWORK_PASSPHRASE,
                base_fee=100,
            )
            .add_text_memo(f"Obius payout ${amount_usd:.6f}")
            .append_payment_op(
                destination=recipient_address,
                asset=Asset.native(),
                amount=str(amount_usd)
            )
            .set_timeout(30)
            .build()
        )
        
        transaction.sign(stellar_keypair)
        response = stellar_server.submit_transaction(transaction)
        
        return response["hash"]
        
    except SdkError as e:
        logging.error(f"Stellar payment failed: {e}")
        raise Exception(f"Payment failed: {str(e)}")
    except Exception as e:
        logging.error(f"Unexpected payment error: {e}")
        raise Exception(f"Payment failed: {str(e)}")

async def get_user_stellar_address(conn, user_type: str, user_id: str) -> Optional[str]:
    """Get user's Stellar address from database"""
    if user_type == "supplier":
        row = await conn.fetchrow("SELECT stellar_address FROM suppliers WHERE id = $1", int(user_id))
    elif user_type == "reviewer":
        row = await conn.fetchrow("SELECT stellar_address FROM reviewers WHERE id = $1", int(user_id))
    else:
        return None
    
    return row["stellar_address"] if row else None

async def process_payouts():
    """Check for accounts ready for payout and process them"""
    if not stellar_keypair:
        logging.warning("Stellar not initialized, skipping payouts")
        return {"processed": 0, "message": "Stellar not configured"}
    
    async with db_pool.acquire() as conn:
        eligible_accounts = await conn.fetch("""
            SELECT user_type, user_id, balance_usd, payout_threshold_usd
            FROM balances 
            WHERE balance_usd >= payout_threshold_usd AND balance_usd > 0
        """)
        
        processed = 0
        results = []
        
        for account in eligible_accounts:
            user_type = account["user_type"]
            user_id = account["user_id"]
            balance = float(account["balance_usd"])
            
            if user_type == "obius":
                continue
                
            recipient_address = await get_user_stellar_address(conn, user_type, user_id)
            if not recipient_address:
                results.append({
                    "user": f"{user_type}/{user_id}",
                    "status": "skipped",
                    "reason": "No Stellar address on file"
                })
                continue
            
            try:
                tx_hash = await send_stellar_payment(recipient_address, balance)
                
                await conn.execute("""
                    INSERT INTO payout_history (stellar_tx_hash, recipient_address, amount_usd, user_type, user_id)
                    VALUES ($1, $2, $3, $4, $5)
                """, tx_hash, recipient_address, balance, user_type, user_id)
                
                await conn.execute("""
                    UPDATE balances SET balance_usd = 0 WHERE user_type = $1 AND user_id = $2
                """, user_type, user_id)
                
                processed += 1
                results.append({
                    "user": f"{user_type}/{user_id}",
                    "amount": balance,
                    "tx_hash": tx_hash,
                    "status": "success"
                })
                
                logging.info(f"Paid out ${balance} to {user_type}/{user_id} - TX: {tx_hash}")
                
            except Exception as e:
                results.append({
                    "user": f"{user_type}/{user_id}",
                    "status": "failed",
                    "error": str(e)
                })
                logging.error(f"Payout failed for {user_type}/{user_id}: {e}")
        
        return {"processed": processed, "results": results}

# Review Processing Functions
async def process_review_consensus(conn, task_id: int):
    """Process consensus when enough reviews are submitted"""
    submissions = await conn.fetch("""
        SELECT * FROM review_submissions WHERE task_id = $1
    """, task_id)
    
    if len(submissions) < 2:
        return
    
    quality_scores = [s["quality_score"] for s in submissions]
    timeliness_scores = [s["timeliness_score"] for s in submissions]
    schema_scores = [s["schema_compliance_score"] for s in submissions]
    overall_ratings = [s["overall_rating"] for s in submissions]
    
    median_overall = statistics.median(overall_ratings)
    consensus_threshold = 2
    
    task = await conn.fetchrow("SELECT * FROM review_tasks WHERE id = $1", task_id)
    reward_per_reviewer = float(task["reward_pool_usd"]) / len(submissions)
    
    for submission in submissions:
        is_consensus = abs(submission["overall_rating"] - median_overall) <= consensus_threshold
        payout = reward_per_reviewer * (1.2 if is_consensus else 0.8)
        
        await conn.execute("""
            UPDATE review_submissions 
            SET is_consensus = $1, payout_earned = $2
            WHERE id = $3
        """, is_consensus, payout, submission["id"])
        
        await conn.execute("""
            UPDATE balances 
            SET balance_usd = balance_usd + $1
            WHERE user_type = 'reviewer' AND user_id = $2
        """, payout, str(submission["reviewer_id"]))
    
    await update_package_quality_scores(conn, task["package_id"], submissions)
    
    await conn.execute("""
        UPDATE review_tasks SET status = 'completed' WHERE id = $1
    """, task_id)
    
    for submission in submissions:
        await update_reviewer_stats(conn, submission["reviewer_id"])

async def update_package_quality_scores(conn, package_id: int, submissions: list):
    """Update aggregated quality scores for a package"""
    avg_quality = statistics.mean([s["quality_score"] for s in submissions])
    avg_timeliness = statistics.mean([s["timeliness_score"] for s in submissions])
    avg_schema = statistics.mean([s["schema_compliance_score"] for s in submissions])
    avg_overall = statistics.mean([s["overall_rating"] for s in submissions])
    
    await conn.execute("""
        UPDATE package_quality_scores SET
            avg_quality_score = $1,
            avg_timeliness_score = $2, 
            avg_schema_score = $3,
            overall_rating = $4,
            total_reviews = total_reviews + $5,
            last_reviewed = NOW(),
            updated_at = NOW()
        WHERE package_id = $6
    """, avg_quality, avg_timeliness, avg_schema, avg_overall, len(submissions), package_id)

async def update_reviewer_stats(conn, reviewer_id: int):
    """Update reviewer statistics after completing a review"""
    stats = await conn.fetchrow("""
        SELECT 
            COUNT(*) as total_reviews,
            AVG(CASE WHEN is_consensus THEN 1.0 ELSE 0.0 END) as consensus_rate,
            SUM(payout_earned) as total_earned
        FROM review_submissions 
        WHERE reviewer_id = $1
    """, reviewer_id)
    
    accuracy_score = min(stats["consensus_rate"] * 10, 10.0) if stats["consensus_rate"] else 0
    
    total_reviews = stats["total_reviews"]
    consensus_rate = float(stats["consensus_rate"] or 0)
    
    if total_reviews >= 100 and consensus_rate >= 0.9:
        reputation_level = "master"
    elif total_reviews >= 50 and consensus_rate >= 0.8:
        reputation_level = "expert" 
    elif total_reviews >= 20 and consensus_rate >= 0.7:
        reputation_level = "experienced"
    else:
        reputation_level = "novice"
    
    await conn.execute("""
        UPDATE reviewer_stats SET
            total_reviews = $1,
            consensus_rate = $2,
            accuracy_score = $3,
            total_earned = $4,
            reputation_level = $5,
            updated_at = NOW()
        WHERE reviewer_id = $6
    """, total_reviews, stats["consensus_rate"], accuracy_score, 
    float(stats["total_earned"]), reputation_level, reviewer_id)
    
    await conn.execute("""
        UPDATE reviewers SET reputation_level = $1 WHERE id = $2
    """, reputation_level, reviewer_id)

# Database Lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    max_retries = 10
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            logging.info(f"Attempting to connect to database (attempt {attempt + 1}/{max_retries})")
            db_pool = await asyncpg.create_pool(DATABASE_URL)
            logging.info("Successfully connected to database")
            
            await add_unique_constraints()
            logging.info("Database migrations completed")
            break
        except Exception as e:
            logging.warning(f"Database connection failed: {e}")
            if attempt == max_retries - 1:
                logging.error("Max retries reached, giving up")
                raise
            logging.info(f"Retrying in {retry_delay} seconds...")
            await asyncio.sleep(retry_delay)
    
    yield
    
    if db_pool:
        await db_pool.close()

# FastAPI App Setup
api = FastAPI(title="Obius", version="0.1.0", lifespan=lifespan)

api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.path.exists("public"):
    api.mount("/static", StaticFiles(directory="public"), name="static")

# Root Endpoints
@api.get("/")
async def serve_catalog():
    """Serve the data catalog as the main page"""
    catalog_path = "public/catalog.html"
    if os.path.exists(catalog_path):
        return FileResponse(catalog_path)
    else:
        return {"message": "Obius API is running", "catalog": "catalog.html not found"}

@api.get("/profile.html")
async def serve_profile():
    """Serve the profile page"""
    return FileResponse("public/profile.html")

@api.get("/catalog.html") 
async def serve_catalog_alt():
    """Alternative catalog route"""
    return FileResponse("public/catalog.html")

@api.get("/validator.html")
async def serve_validator():
    """Serve the validator page"""
    return FileResponse("public/validator.html")

@api.get("/upload.html")
async def serve_upload():
    """Serve the upload page"""
    return FileResponse("public/upload.html")

@api.get("/auth.html")
async def serve_auth():
    """Serve the authentication page"""
    auth_path = "public/auth.html"
    if os.path.exists(auth_path):
        return FileResponse(auth_path)
    else:
        raise HTTPException(status_code=404, detail="Auth page not found")

@api.get("/health")
def health():
    return {"ok": True}

# Authentication Endpoints
@api.get("/auth/check-username")
async def check_username_availability(username: str):
    """Check if username is available"""
    async with db_pool.acquire() as conn:
        existing = await conn.fetchval(
            "SELECT username FROM users WHERE username = $1", 
            username
        )
        
        available = existing is None
        return {
            "available": available,
            "message": "Username is available" if available else "Username is already taken"
        }

@api.get("/auth/check-email")
async def check_email_availability(email: str):
    """Check if email is available"""
    if not email or '@' not in email:
        return {
            "available": False,
            "message": "Please enter a valid email address"
        }
    
    email = email.strip().lower()
    
    try:
        async with db_pool.acquire() as conn:
            existing = await conn.fetchval(
                "SELECT email FROM users WHERE LOWER(email) = $1", 
                email
            )
            
            available = existing is None
            message = "Email is available" if available else "Email is already registered"
            
            return {
                "available": available,
                "message": message
            }
            
    except Exception as e:
        return {
            "available": False,
            "message": f"Database error: {str(e)}"
        }

@api.post("/auth/register")
async def register_user(user_data: UserRegistration):
    """Register a new user with unified authentication - ONLY usr_ keys"""
    async with db_pool.acquire() as conn:
        # Check for existing username
        existing_username = await conn.fetchval(
            "SELECT username FROM users WHERE username = $1", 
            user_data.username
        )
        if existing_username:
            raise HTTPException(status_code=409, detail="Username already taken")
        
        # Check for existing email
        existing_email = await conn.fetchval(
            "SELECT email FROM users WHERE email = $1", 
            user_data.email
        )
        if existing_email:
            raise HTTPException(status_code=409, detail="Email already registered")
        
        password_hash = hash_password(user_data.password)
        api_key = f"usr_{secrets.token_urlsafe(32)}"  # This line should be properly indented
        
        try:
            async with conn.transaction():
                # Create user
                user_id = await conn.fetchval("""
                    INSERT INTO users (username, name, email, password_hash, stellar_address)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                """, user_data.username, user_data.name, user_data.email, 
                password_hash, user_data.stellar_address)
                
                # Create user roles
                for role in user_data.roles:
                    await conn.execute("""
                        INSERT INTO user_roles (user_id, role_type, api_key)
                        VALUES ($1, $2, $3)
                    """, user_id, role, api_key)
                
                # Create role-specific records
                if 'supplier' in user_data.roles:
                    # Create supplier record
                    await conn.execute("""
                        INSERT INTO suppliers (id, name, email, stellar_address, api_key, status)
                        VALUES ($1, $2, $3, $4, $5, 'active')
                        ON CONFLICT (id) DO NOTHING
                    """, user_id, user_data.name, user_data.email, user_data.stellar_address, api_key)
                    
                    # Create supplier balance
                    await conn.execute("""
                        INSERT INTO balances (user_type, user_id, payout_threshold_usd)
                        VALUES ('supplier', $1, 25.00)
                        ON CONFLICT (user_type, user_id) DO NOTHING
                    """, str(user_id))
                
                if 'reviewer' in user_data.roles:
                    # Create reviewer record first
                    await conn.execute("""
                        INSERT INTO reviewers (id, name, email, stellar_address, api_key)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (id) DO NOTHING
                    """, user_id, user_data.name, user_data.email, user_data.stellar_address, api_key)
                    
                    # Create reviewer balance
                    await conn.execute("""
                        INSERT INTO balances (user_type, user_id, payout_threshold_usd)
                        VALUES ('reviewer', $1, 5.00)
                        ON CONFLICT (user_type, user_id) DO NOTHING
                    """, str(user_id))
                    
                    # Create reviewer stats
                    await conn.execute("""
                        INSERT INTO reviewer_stats (reviewer_id) 
                        VALUES ($1)
                        ON CONFLICT (reviewer_id) DO NOTHING
                    """, user_id)
                
                return {
                    "user_id": user_id,
                    "username": user_data.username,
                    "api_key": api_key,
                    "roles": user_data.roles,
                    "message": "Account created successfully"
                }
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@api.post("/auth/login")
async def login_user(credentials: LoginCredentials):
    """Login with username and password"""
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("""
            SELECT u.id, u.username, u.name, u.email, u.password_hash, u.stellar_address
            FROM users u
            WHERE u.username = $1
        """, credentials.username)
        
        if not user or not verify_password(credentials.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        roles_data = await conn.fetch("""
            SELECT role_type, api_key FROM user_roles 
            WHERE user_id = $1 AND is_active = TRUE
        """, user["id"])
        
        if not roles_data:
            raise HTTPException(status_code=401, detail="No active roles found")
        
        roles = [role["role_type"] for role in roles_data]
        api_key = roles_data[0]["api_key"]
        
        session_token = generate_session_token()
        session_data = UserSession(
            user_id=user["id"],
            username=user["username"],
            name=user["name"],
            email=user["email"],
            roles=roles,
            api_key=api_key,
            stellar_address=user["stellar_address"]
        )
        
        active_sessions[session_token] = {
            "data": session_data,
            "expires_at": datetime.now() + timedelta(hours=24)
        }
        
        return {
            "session_token": session_token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "name": user["name"],
                "email": user["email"],
                "roles": roles,
                "api_key": api_key,
                "stellar_address": user["stellar_address"]
            }
        }

@api.post("/auth/logout")
async def logout_user(session_token: str = Header(None, alias="Authorization")):
    """Logout user and invalidate session"""
    if session_token and session_token in active_sessions:
        del active_sessions[session_token]
    
    return {"message": "Logged out successfully"}

@api.get("/auth/session")
async def get_session(session_token: str = Header(None, alias="Authorization")):
    """Get current session data"""
    if not session_token or session_token not in active_sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    session = active_sessions[session_token]
    
    if datetime.now() > session["expires_at"]:
        del active_sessions[session_token]
        raise HTTPException(status_code=401, detail="Session expired")
    
    return {"user": session["data"]}

# Unified Upload Endpoint (replaces both old endpoints)
@api.post("/users/upload")
async def upload_dataset_unified(
    file: UploadFile = File(...),
    name: str = Form(...),
    description: str = Form(""),
    category: str = Form("financial"),
    price_per_query: float = Form(0.005),
    tags: str = Form(""),
    x_api_key: Optional[str] = Header(None)
):
    """Upload dataset using unified authentication system"""
    # Authenticate using unified system
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    async with db_pool.acquire() as conn:
        # Check if user exists and has supplier role
        user_role = await conn.fetchrow("""
            SELECT ur.user_id, u.name, u.email 
            FROM user_roles ur
            JOIN users u ON ur.user_id = u.id
            WHERE ur.api_key = $1 AND ur.role_type = 'supplier' AND ur.is_active = TRUE
        """, x_api_key)
        
        if not user_role:
            raise HTTPException(status_code=401, detail="Invalid API key or not authorized as supplier")
        
        user_id = user_role["user_id"]
        user_name = user_role["name"]
    
    # Validate file
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files supported")
    
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    
    # Generate secure filename
    file_hash = hashlib.sha256(content).hexdigest()[:16]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{user_id}_{timestamp}_{file_hash}.csv"
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    temp_path = file_path + ".temp"
    with open(temp_path, 'wb') as f:
        f.write(content)
    
    try:
        df = pd.read_csv(temp_path)
        detector = PIIDetector()
        analysis = detector.scan_dataframe(df)
        
        async with db_pool.acquire() as conn:
            # Log PII detection
            for pii_type, count in analysis['findings_by_type'].items():
                action = 'block' if analysis['blocking_issues'] else 'allow'
                blocked = len(analysis['blocking_issues']) > 0
                
                await conn.execute("""
                    INSERT INTO pii_detection_log 
                    (supplier_id, filename, pii_type, action_taken, findings_count, blocked, detection_details)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                """, user_id, filename, pii_type, action, count, blocked, json.dumps(analysis))
            
            # Block if PII issues found
            if analysis['blocking_issues']:
                os.remove(temp_path)
                
                blocking_summary = {}
                for issue in analysis['blocking_issues']:
                    pii_type = issue['type']
                    if pii_type not in blocking_summary:
                        blocking_summary[pii_type] = 0
                    blocking_summary[pii_type] += 1
                
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "PII_DETECTED",
                        "message": "Upload blocked due to sensitive data detection",
                        "pii_found": blocking_summary,
                        "findings_count": analysis['total_findings'],
                        "recommendation": "Please remove or anonymize sensitive data before uploading"
                    }
                )
            
            # Clean data if needed
            cleaned_df, cleaning_log = detector.clean_dataframe(df, analysis)
            
            # Save cleaned file
            cleaned_df.to_csv(file_path, index=False)
            os.remove(temp_path)
            
            # Prepare metadata
            sample_data = cleaned_df.head(3).to_dict(orient='records')
            schema = {col: str(cleaned_df[col].dtype) for col in cleaned_df.columns}
            row_count = len(cleaned_df)
            column_count = len(cleaned_df.columns)
            
            tag_list = [tag.strip() for tag in tags.split(',')] if tags else []
            tag_list.extend(['uploaded', 'pii-filtered'])
            
            # Create data package
            package_id = await conn.fetchval("""
                INSERT INTO data_packages (
                    supplier_id, name, description, category, 
                    endpoint_url, price_per_query, sample_data, 
                    tags, package_type
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING id
            """, user_id, name, description, category,
            f"/data/uploaded/{filename}", price_per_query, 
            json.dumps(sample_data), tag_list, 'upload')
            
            # Store upload metadata
            await conn.execute("""
                INSERT INTO uploaded_datasets (
                    supplier_id, package_id, filename, original_filename,
                    file_path, file_size, file_hash, data_format,
                    row_count, column_count, schema_info
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            """, user_id, package_id, filename, file.filename,
            file_path, len(content), file_hash, 'csv',
            row_count, column_count, json.dumps(schema))
            
            response = {
                "package_id": package_id,
                "filename": filename,
                "status": "uploaded",
                "row_count": row_count,
                "column_count": column_count,
                "message": f"Dataset '{name}' uploaded successfully by {user_name}",
                "pii_analysis": {
                    "scanned": True,
                    "findings_total": analysis['total_findings'],
                    "pii_types_found": list(analysis['findings_by_type'].keys()),
                    "actions_taken": cleaning_log['actions_taken'] if cleaning_log['actions_taken'] else ["No PII cleaning needed"],
                    "data_cleaned": len(cleaning_log['actions_taken']) > 0
                }
            }
            
            return response
            
    except pd.errors.ParserError as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(status_code=400, detail=f"Invalid CSV file: {str(e)}")
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
async def authenticate_unified_user(api_key: str, required_role: str = None):
    """Authenticate user by unified API key and optionally check role"""
    if not api_key or not api_key.startswith('usr_'):
        raise HTTPException(status_code=401, detail="Invalid API key format. Expected usr_ key.")
    
    async with db_pool.acquire() as conn:
        user_role = await conn.fetchrow("""
            SELECT ur.user_id, u.name, u.email, u.stellar_address
            FROM user_roles ur
            JOIN users u ON ur.user_id = u.id
            WHERE ur.api_key = $1 AND ur.is_active = TRUE
        """, api_key)
        
        if not user_role:
            raise HTTPException(status_code=401, detail="Invalid or inactive API key")
        
        # Get all roles for this user
        all_roles = await conn.fetch("""
            SELECT role_type FROM user_roles WHERE user_id = $1 AND is_active = TRUE
        """, user_role["user_id"])
        
        roles = [role["role_type"] for role in all_roles]
        
        # Check if user has required role
        if required_role and required_role not in roles:
            raise HTTPException(status_code=403, detail=f"User does not have required role: {required_role}")
        
        return {
            "user_id": user_role["user_id"],
            "name": user_role["name"],
            "email": user_role["email"],
            "stellar_address": user_role["stellar_address"],
            "roles": roles,
            "api_key": api_key
        }



# ============================================================================
# API ENDPOINTS - Add to app.py
# ============================================================================

# Get available validation tasks
@api.get("/validation-tasks")
async def get_available_validation_tasks(
    validation_type: Optional[str] = None,
    x_api_key: Optional[str] = Header(None)
):
    """Get available validation tasks - uses unified usr_ auth"""
    user = await authenticate_unified_user(x_api_key, required_role="validator")
    
    async with db_pool.acquire() as conn:
        query = """
            SELECT vt.*, dp.name as package_name, dp.category, 
                   u.name as supplier_name,
                   (vt.required_validations - COALESCE(submitted_count.count, 0)) as spots_remaining
            FROM validation_tasks vt
            JOIN data_packages dp ON vt.package_id = dp.id
            JOIN users u ON dp.supplier_id = u.id
            LEFT JOIN (
                SELECT task_id, COUNT(*) as count 
                FROM validation_submissions 
                GROUP BY task_id
            ) submitted_count ON vt.id = submitted_count.task_id
            WHERE vt.status = 'open' 
            AND vt.expires_at > NOW()
            AND vt.id NOT IN (
                SELECT task_id FROM validation_submissions WHERE validator_id = $1
            )
            AND (vt.required_validations - COALESCE(submitted_count.count, 0)) > 0
        """
        
        params = [user["user_id"]]
        
        if validation_type:
            query += " AND vt.validation_type = $2"
            params.append(validation_type)
        
        query += " ORDER BY vt.reward_pool_usd DESC, vt.created_at ASC LIMIT 20"
        
        tasks = await conn.fetch(query, *params)
        
        return [
            {
                "task_id": task["id"],
                "package_name": task["package_name"],
                "supplier": task["supplier_name"],
                "category": task["category"],
                "validation_type": task["validation_type"],
                "reward_pool": float(task["reward_pool_usd"]),
                "spots_remaining": task["spots_remaining"],
                "reference_data": task["reference_data"],
                "expires_at": task["expires_at"].isoformat()
            }
            for task in tasks
        ]

# Submit validation
# Add this endpoint to your app.py

@api.post("/validation-tasks/{task_id}/submit")
async def submit_validation(
    task_id: int,
    validation: dict,  # Contains: passed, confidence_score, notes, validation_data
    x_api_key: Optional[str] = Header(None)
):
    """Submit a validation for a task - uses unified usr_ auth"""
    user = await authenticate_unified_user(x_api_key, required_role="validator")
    
    async with db_pool.acquire() as conn:
        # Get task
        task = await conn.fetchrow("""
            SELECT vt.*, dp.package_type, dp.name as package_name
            FROM validation_tasks vt
            JOIN data_packages dp ON vt.package_id = dp.id
            WHERE vt.id = $1 AND vt.status = 'open' AND vt.expires_at > NOW()
        """, task_id)
        
        if not task:
            raise HTTPException(status_code=404, detail="Task not found or expired")
        
        # Check if already submitted
        existing = await conn.fetchval("""
            SELECT id FROM validation_submissions 
            WHERE task_id = $1 AND validator_id = $2
        """, task_id, user["user_id"])
        
        if existing:
            raise HTTPException(status_code=409, detail="Already submitted validation for this task")
        
        # Insert validation submission
        submission_id = await conn.fetchval("""
            INSERT INTO validation_submissions (
                task_id, 
                validator_id, 
                validation_type,
                passed,
                confidence_score,
                validation_data,
                notes,
                submitted_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            RETURNING id
        """, task_id, user["user_id"], task["validation_type"],
        validation["passed"], validation.get("confidence_score", 0.8),
        json.dumps(validation.get("validation_data", {})), 
        validation.get("notes", ""))
        
        logging.info(f"Validation submission {submission_id} created by validator {user['user_id']} for task {task_id}")
        
        # Check if we have enough submissions for consensus
        submission_count = await conn.fetchval("""
            SELECT COUNT(*) FROM validation_submissions WHERE task_id = $1
        """, task_id)
        
        logging.info(f"Task {task_id} now has {submission_count}/{task['required_validations']} submissions")
        
        if submission_count >= task["required_validations"]:
            logging.info(f"Task {task_id} reached required validations, processing consensus...")
            await process_validation_consensus(conn, task_id)
        
        return {
            "submission_id": submission_id,
            "status": "submitted",
            "task_name": task["package_name"],
            "submissions_count": submission_count,
            "required_count": task["required_validations"],
            "message": f"Validation submitted. {task['required_validations'] - submission_count} more validations needed for consensus."
        }

# Get validator profile
@api.get("/validators/me")  
async def get_validator_info(x_api_key: Optional[str] = Header(None)):
    """Get validator information - uses unified usr_ auth"""
    user = await authenticate_unified_user(x_api_key, required_role="validator")
    
    async with db_pool.acquire() as conn:
        # Get validator stats
        stats = await conn.fetchrow("""
            SELECT vs.*, b.balance_usd, b.payout_threshold_usd
            FROM validator_stats vs
            LEFT JOIN balances b ON vs.validator_id::text = b.user_id AND b.user_type = 'validator'
            WHERE vs.validator_id = $1
        """, user["user_id"])
        
        if not stats:
            # Create initial stats if they don't exist
            await conn.execute("""
                INSERT INTO validator_stats (validator_id) 
                VALUES ($1)
                ON CONFLICT (validator_id) DO NOTHING
            """, user["user_id"])
            
            # Create balance entry
            await conn.execute("""
                INSERT INTO balances (user_type, user_id, payout_threshold_usd)
                VALUES ('validator', $1, 5.00)
                ON CONFLICT (user_type, user_id) DO NOTHING
            """, str(user["user_id"]))
            
            # Fetch again
            stats = await conn.fetchrow("""
                SELECT vs.*, b.balance_usd, b.payout_threshold_usd
                FROM validator_stats vs
                LEFT JOIN balances b ON vs.validator_id::text = b.user_id AND b.user_type = 'validator'
                WHERE vs.validator_id = $1
            """, user["user_id"])
        
        return {
            "id": user["user_id"],
            "name": user["name"],
            "email": user["email"],
            "reputation_level": stats["reputation_level"] if stats else "novice_validator",
            "stats": {
                "total_validations": stats["total_validations"] if stats else 0,
                "consensus_rate": float(stats["consensus_rate"] or 0) if stats else 0,
                "avg_confidence": float(stats["avg_confidence"] or 0) if stats else 0,
                "total_earned": float(stats["total_earned"] or 0) if stats else 0
            },
            "balance": float(stats["balance_usd"] or 0) if stats else 0,
            "payout_threshold": float(stats["payout_threshold_usd"] or 5.00) if stats else 5.00
        }
# Add this endpoint after the existing /validators/me endpoint

@api.get("/validators/me/history")
async def get_validator_history(x_api_key: Optional[str] = Header(None)):
    """Get validator's submission history"""
    user = await authenticate_unified_user(x_api_key, required_role="validator")
    
    async with db_pool.acquire() as conn:
        submissions = await conn.fetch("""
            SELECT 
                vs.id,
                vs.task_id,
                vt.validation_type,
                vs.passed,
                vs.confidence_score,
                vs.notes,
                vs.submitted_at,
                vs.payout_earned,
                dp.name as package_name,
                dp.category
            FROM validation_submissions vs
            JOIN validation_tasks vt ON vs.task_id = vt.id
            JOIN data_packages dp ON vt.package_id = dp.id
            WHERE vs.validator_id = $1
            ORDER BY vs.submitted_at DESC
            LIMIT 50
        """, user["user_id"])
        
        return [
            {
                "id": sub["id"],
                "task_id": sub["task_id"],
                "package_name": sub["package_name"],
                "category": sub["category"],
                "validation_type": sub["validation_type"],
                "passed": sub["passed"],
                "confidence_score": float(sub["confidence_score"]),
                "notes": sub["notes"],
                "payout_earned": float(sub["payout_earned"] or 0),
                "submitted_at": sub["submitted_at"].isoformat()
            }
            for sub in submissions
        ]
# Get package validation status
@api.get("/packages/{package_id}/validation")
async def get_package_validation(package_id: int):
    """Get validation status for a data package"""
    async with db_pool.acquire() as conn:
        validation = await conn.fetchrow("""
            SELECT pvs.*, dp.name as package_name, s.name as supplier_name
            FROM package_validation_scores pvs
            JOIN data_packages dp ON pvs.package_id = dp.id
            JOIN suppliers s ON dp.supplier_id = s.id
            WHERE pvs.package_id = $1
        """, package_id)
        
        if not validation:
            return {
                "package_id": package_id,
                "validated": False,
                "message": "No validation data available"
            }
        
        # Get recent validations
        recent_validations = await conn.fetch("""
            SELECT vs.validation_type, vs.passed, vs.confidence_score, vs.submitted_at,
                   u.name as validator_name
            FROM validation_submissions vs
            JOIN validation_tasks vt ON vs.task_id = vt.id
            JOIN users u ON vs.validator_id = u.id
            WHERE vt.package_id = $1
            ORDER BY vs.submitted_at DESC
            LIMIT 10
        """, package_id)
        
        return {
            "package_id": package_id,
            "package_name": validation["package_name"],
            "supplier": validation["supplier_name"],
            "validated": True,
            "consensus_score": float(validation["consensus_score"]),
            "validation_badges": validation["validation_badges"],
            "total_validations": validation["total_validations"],
            "last_validated": validation["last_validated"].isoformat() if validation["last_validated"] else None,
            "recent_validations": [
                {
                    "type": v["validation_type"],
                    "passed": v["passed"],
                    "confidence": float(v["confidence_score"]),
                    "validator": v["validator_name"],
                    "date": v["submitted_at"].isoformat()
                }
                for v in recent_validations
            ]
        }

# Admin endpoint to create validation task
@api.post("/admin/create-validation-task")
async def create_validation_task_endpoint(
    package_id: int,
    validation_type: str,
    reward_pool: float = 0.10
):
    """Admin endpoint to manually create validation tasks"""
    async with db_pool.acquire() as conn:
        task_id = await create_validation_task(conn, package_id, validation_type, reward_pool)
        
        return {
            "task_id": task_id,
            "status": "created",
            "validation_type": validation_type,
            "reward_pool": reward_pool
        }



# Legacy Supplier Endpoints (for backward compatibility)
@api.post("/suppliers/register")
async def register_supplier(supplier: SupplierRegistration):
    """Register a new data supplier (legacy endpoint)"""
    async with db_pool.acquire() as conn:
        existing_email = await conn.fetchval("""
            SELECT email FROM suppliers WHERE email = $1
            UNION
            SELECT email FROM reviewers WHERE email = $1
        """, supplier.email)
        
        if existing_email:
            raise HTTPException(status_code=409, detail="Email already registered")
        
        existing_name = await conn.fetchval("""
            SELECT name FROM suppliers WHERE name = $1
            UNION
            SELECT name FROM reviewers WHERE name = $1
        """, supplier.name)
        
        if existing_name:
            raise HTTPException(status_code=409, detail="Username already taken")
        
        existing_stellar = await conn.fetchval("""
            SELECT stellar_address FROM suppliers WHERE stellar_address = $1
            UNION
            SELECT stellar_address FROM reviewers WHERE stellar_address = $1
        """, supplier.stellar_address)
        
        if existing_stellar:
            raise HTTPException(status_code=409, detail="Stellar address already registered")
        
        api_key = f"sup_{secrets.token_urlsafe(32)}"
        
        try:
            supplier_id = await conn.fetchval("""
                INSERT INTO suppliers (name, email, stellar_address, api_key)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            """, supplier.name, supplier.email, supplier.stellar_address, api_key)
            
            await conn.execute("""
                INSERT INTO balances (user_type, user_id, payout_threshold_usd)
                VALUES ('supplier', $1, 25.00)
            """, str(supplier_id))
            
            return {
                "supplier_id": supplier_id,
                "api_key": api_key,
                "status": "registered",
                "message": "Supplier registered successfully. Save your API key securely."
            }
            
        except Exception as e:
            error_msg = str(e).lower()
            if "email" in error_msg and "unique" in error_msg:
                raise HTTPException(status_code=409, detail="Email already registered")
            elif "name" in error_msg and "unique" in error_msg:
                raise HTTPException(status_code=409, detail="Username already taken")
            elif "stellar_address" in error_msg and "unique" in error_msg:
                raise HTTPException(status_code=409, detail="Stellar address already registered")
            else:
                raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@api.get("/suppliers/me")
async def get_supplier_info(x_api_key: Optional[str] = Header(None)):
    """Get supplier information - now works with usr_ keys"""
    user = await authenticate_unified_user(x_api_key, required_role="supplier")
    
    async with db_pool.acquire() as conn:
        supplier_info = await conn.fetchrow("""
            SELECT 
                COUNT(dp.id) as package_count,
                b.balance_usd,
                b.payout_threshold_usd
            FROM users u
            LEFT JOIN data_packages dp ON u.id = dp.supplier_id
            LEFT JOIN balances b ON u.id::text = b.user_id AND b.user_type = 'supplier'
            WHERE u.id = $1
            GROUP BY b.balance_usd, b.payout_threshold_usd
        """, user["user_id"])
        
        return {
            "id": user["user_id"],
            "name": user["name"],
            "email": user["email"],
            "stellar_address": user["stellar_address"],
            "status": "active",
            "package_count": supplier_info["package_count"] if supplier_info else 0,
            "balance": float(supplier_info["balance_usd"] or 0) if supplier_info else 0,
            "payout_threshold": float(supplier_info["payout_threshold_usd"] or 25.00) if supplier_info else 25.00,
            "created_at": "2025-01-01T00:00:00"
        }
        

@api.post("/suppliers/packages")
async def create_package(package: DataPackage, x_api_key: Optional[str] = Header(None)):
    """Create a new data package"""
    user = await authenticate_unified_user(x_api_key, required_role="supplier")

    async with db_pool.acquire() as conn:
        package_id = await conn.fetchval("""
            INSERT INTO data_packages (
                supplier_id, name, description, category, endpoint_url,
                price_per_query, sample_data, schema_definition, rate_limit, tags
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
        """, user["user_id"], package.name, package.description, package.category,
        package.endpoint_url, package.price_per_query, package.sample_data,
        package.schema_definition, package.rate_limit, package.tags)
        
        return {
            "package_id": package_id,
            "status": "created",
            "message": "Data package created successfully"
        }

@api.get("/suppliers/uploads")
async def list_uploads(x_api_key: Optional[str] = Header(None)):
    """List supplier's uploaded datasets - now works with usr_ keys"""
    user = await authenticate_unified_user(x_api_key, required_role="supplier")
    
    async with db_pool.acquire() as conn:
        uploads = await conn.fetch("""
            SELECT ud.*, dp.name as package_name
            FROM uploaded_datasets ud
            JOIN data_packages dp ON ud.package_id = dp.id
            WHERE ud.supplier_id = $1
            ORDER BY ud.upload_date DESC
        """, user["user_id"])
        
        return [
            {
                "package_id": upload["package_id"],
                "package_name": upload["package_name"],
                "filename": upload["filename"],
                "original_filename": upload["original_filename"],
                "file_size": upload["file_size"],
                "row_count": upload["row_count"],
                "upload_date": upload["upload_date"].isoformat()
            }
            for upload in uploads
        ]

# Reviewer Endpoints
@api.post("/reviewers/register")
async def register_reviewer(reviewer: ReviewerRegistration):
    """Register as a data quality reviewer"""
    async with db_pool.acquire() as conn:
        existing_email = await conn.fetchval("""
            SELECT email FROM reviewers WHERE email = $1
            UNION
            SELECT email FROM suppliers WHERE email = $1
        """, reviewer.email)
        
        if existing_email:
            raise HTTPException(status_code=409, detail="Email already registered")
        
        existing_name = await conn.fetchval("""
            SELECT name FROM reviewers WHERE name = $1
            UNION
            SELECT name FROM suppliers WHERE name = $1
        """, reviewer.name)
        
        if existing_name:
            raise HTTPException(status_code=409, detail="Username already taken")
        
        existing_stellar = await conn.fetchval("""
            SELECT stellar_address FROM reviewers WHERE stellar_address = $1
            UNION
            SELECT stellar_address FROM suppliers WHERE stellar_address = $1
        """, reviewer.stellar_address)
        
        if existing_stellar:
            raise HTTPException(status_code=409, detail="Stellar address already registered")
        
        api_key = f"rev_{secrets.token_urlsafe(32)}"
        
        try:
            reviewer_id = await conn.fetchval("""
                INSERT INTO reviewers (name, stellar_address, email, specializations, api_key)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
            """, reviewer.name, reviewer.stellar_address, reviewer.email, 
            reviewer.specializations, api_key)
            
            await conn.execute("""
                INSERT INTO balances (user_type, user_id, payout_threshold_usd)
                VALUES ('reviewer', $1, 5.00)
            """, str(reviewer_id))
            
            await conn.execute("""
                INSERT INTO reviewer_stats (reviewer_id) VALUES ($1)
            """, reviewer_id)
            
            return {
                "reviewer_id": reviewer_id,
                "api_key": api_key,
                "status": "registered",
                "message": "Reviewer registered successfully. Save your API key securely."
            }
            
        except Exception as e:
            error_msg = str(e).lower()
            if "email" in error_msg and "unique" in error_msg:
                raise HTTPException(status_code=409, detail="Email already registered")
            elif "name" in error_msg and "unique" in error_msg:
                raise HTTPException(status_code=409, detail="Username already taken") 
            elif "stellar_address" in error_msg and "unique" in error_msg:
                raise HTTPException(status_code=409, detail="Stellar address already registered")
            else:
                raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@api.get("/reviewers/me")  
async def get_reviewer_info(x_api_key: Optional[str] = Header(None)):
    """Get reviewer information - now works with usr_ keys"""
    user = await authenticate_unified_user(x_api_key, required_role="reviewer")
    
    async with db_pool.acquire() as conn:
        info = await conn.fetchrow("""
            SELECT r.*, rs.*, b.balance_usd, b.payout_threshold_usd
            FROM reviewers r
            LEFT JOIN reviewer_stats rs ON r.id = rs.reviewer_id
            LEFT JOIN balances b ON r.id::text = b.user_id AND b.user_type = 'reviewer'
            WHERE r.id = $1
        """, reviewer["id"])
        
        return {
            "id": info["id"],
            "name": info["name"],
            "stellar_address": info["stellar_address"],
            "reputation_level": info["reputation_level"],
            "specializations": info["specializations"] or [],
            "stats": {
                "total_reviews": info["total_reviews"] or 0,
                "consensus_rate": float(info["consensus_rate"] or 0),
                "accuracy_score": float(info["accuracy_score"] or 0),
                "total_earned": float(info["total_earned"] or 0),
                "avg_review_time_minutes": info["avg_review_time_minutes"] or 0
            },
            "balance": float(info["balance_usd"] or 0),
            "payout_threshold": float(info["payout_threshold_usd"] or 5.00)
        }

@api.get("/review-tasks")
async def get_available_review_tasks(
    category: Optional[str] = None,
    task_type: Optional[str] = None,
    x_api_key: Optional[str] = Header(None)
):
    """Get available review tasks for a reviewer"""
    user = await authenticate_unified_user(x_api_key, required_role="reviewer")
    
    async with db_pool.acquire() as conn:
        query = """
            SELECT rt.*, dp.name as package_name, dp.category, s.name as supplier_name,
                   pqs.overall_rating as current_rating,
                   (rt.required_reviews - COALESCE(submitted_count.count, 0)) as spots_remaining
            FROM review_tasks rt
            JOIN data_packages dp ON rt.package_id = dp.id
            JOIN suppliers s ON dp.supplier_id = s.id
            LEFT JOIN package_quality_scores pqs ON dp.id = pqs.package_id
            LEFT JOIN (
                SELECT task_id, COUNT(*) as count 
                FROM review_submissions 
                GROUP BY task_id
            ) submitted_count ON rt.id = submitted_count.task_id
            WHERE rt.status = 'open' 
            AND rt.expires_at > NOW()
            AND rt.id NOT IN (
                SELECT task_id FROM review_submissions WHERE reviewer_id = $1
            )
            AND (rt.required_reviews - COALESCE(submitted_count.count, 0)) > 0
        """
        
        params = [reviewer["id"]]
        
        if category:
            query += " AND dp.category = $2"
            params.append(category)
        
        if task_type:
            query += f" AND rt.task_type = ${'3' if category else '2'}"
            params.append(task_type)
        
        query += " ORDER BY rt.reward_pool_usd DESC, rt.created_at ASC LIMIT 20"
        
        tasks = await conn.fetch(query, *params)
        
        return [
            {
                "task_id": task["id"],
                "package_name": task["package_name"],
                "supplier": task["supplier_name"],
                "category": task["category"],
                "task_type": task["task_type"],
                "reward_pool": float(task["reward_pool_usd"]),
                "spots_remaining": task["spots_remaining"],
                "current_rating": float(task["current_rating"] or 0),
                "reference_query": task["reference_query"],
                "expires_at": task["expires_at"].isoformat()
            }
            for task in tasks
        ]

@api.post("/review-tasks/{task_id}/submit")
async def submit_review(
    task_id: int,
    review: ReviewSubmission,
    x_api_key: Optional[str] = Header(None)
):
    """Submit a quality review for a task"""
    user = await authenticate_unified_user(x_api_key, required_role="reviewer")
    
    async with db_pool.acquire() as conn:
        task = await conn.fetchrow("""
            SELECT rt.*, dp.name as package_name
            FROM review_tasks rt
            JOIN data_packages dp ON rt.package_id = dp.id
            WHERE rt.id = $1 AND rt.status = 'open' AND rt.expires_at > NOW()
        """, task_id)
        
        if not task:
            raise HTTPException(status_code=404, detail="Task not found or expired")
        
        existing = await conn.fetchval("""
            SELECT id FROM review_submissions 
            WHERE task_id = $1 AND reviewer_id = $2
        """, task_id, reviewer["id"])
        
        if existing:
            raise HTTPException(status_code=409, detail="Already submitted review for this task")
        
        submission_id = await conn.fetchval("""
            INSERT INTO review_submissions (
                task_id, reviewer_id, quality_score, timeliness_score, 
                schema_compliance_score, overall_rating, findings, evidence,
                test_timestamp
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            RETURNING id
        """, task_id, reviewer["id"], review.quality_score, review.timeliness_score,
        review.schema_compliance_score, review.overall_rating, review.findings, 
        json.dumps(review.evidence) if review.evidence else None)
        
        review_count = await conn.fetchval("""
            SELECT COUNT(*) FROM review_submissions WHERE task_id = $1
        """, task_id)
        
        if review_count >= task["required_reviews"]:
            await process_review_consensus(conn, task_id)
        
        return {
            "submission_id": submission_id,
            "status": "submitted",
            "task_name": task["package_name"],
            "message": f"Review submitted. {task['required_reviews'] - review_count} more reviews needed for consensus."
        }

# Package and Data Endpoints
@api.get("/packages")
async def list_packages(category: Optional[str] = None, tag: Optional[str] = None):
    """List all available data packages"""
    async with db_pool.acquire() as conn:
        query = """
            SELECT p.*, s.name as supplier_name
            FROM data_packages p
            JOIN suppliers s ON p.supplier_id = s.id
            WHERE p.status = 'active' AND s.status = 'active'
        """
        params = []
        
        if category:
            query += " AND p.category = $1"
            params.append(category)
        
        if tag:
            query += f" AND ${'2' if category else '1'} = ANY(p.tags)"
            params.append(tag)
        
        query += " ORDER BY p.created_at DESC"
        
        packages = await conn.fetch(query, *params)
        
        return [
            {
                "id": pkg["id"],
                "name": pkg["name"],
                "description": pkg["description"],
                "category": pkg["category"],
                "supplier": pkg["supplier_name"],
                "price_per_query": float(pkg["price_per_query"]),
                "sample_data": pkg["sample_data"],
                "tags": pkg["tags"],
                "rate_limit": pkg["rate_limit"]
            }
            for pkg in packages
        ]

@api.get("/packages/{package_id}")
async def get_package(package_id: int):
    """Get detailed package information"""
    async with db_pool.acquire() as conn:
        package = await conn.fetchrow("""
            SELECT p.*, s.name as supplier_name
            FROM data_packages p
            JOIN suppliers s ON p.supplier_id = s.id
            WHERE p.id = $1 AND p.status = 'active' AND s.status = 'active'
        """, package_id)
        
        if not package:
            raise HTTPException(status_code=404, detail="Package not found")
        
        return {
            "id": package["id"],
            "name": package["name"],
            "description": package["description"],
            "category": package["category"],
            "supplier": package["supplier_name"],
            "price_per_query": float(package["price_per_query"]),
            "sample_data": package["sample_data"],
            "schema_definition": package["schema_definition"],
            "tags": package["tags"],
            "rate_limit": package["rate_limit"],
            "created_at": package["created_at"].isoformat()
        }

@api.get("/packages/{package_id}/quality")
async def get_package_quality(package_id: int):
    """Get quality assessment for a data package"""
    async with db_pool.acquire() as conn:
        quality = await conn.fetchrow("""
            SELECT pqs.*, dp.name as package_name, s.name as supplier_name
            FROM package_quality_scores pqs
            JOIN data_packages dp ON pqs.package_id = dp.id
            JOIN suppliers s ON dp.supplier_id = s.id
            WHERE pqs.package_id = $1
        """, package_id)
        
        if not quality:
            raise HTTPException(status_code=404, detail="Package not found")
        
        recent_reviews = await conn.fetch("""
            SELECT rs.overall_rating, rs.findings, rs.submitted_at, r.name as reviewer_name
            FROM review_submissions rs
            JOIN review_tasks rt ON rs.task_id = rt.id
            JOIN reviewers r ON rs.reviewer_id = r.id
            WHERE rt.package_id = $1
            ORDER BY rs.submitted_at DESC
            LIMIT 10
        """, package_id)
        
        return {
            "package_id": package_id,
            "package_name": quality["package_name"],
            "supplier": quality["supplier_name"],
            "scores": {
                "overall_rating": float(quality["overall_rating"]),
                "quality": float(quality["avg_quality_score"]),
                "timeliness": float(quality["avg_timeliness_score"]),
                "schema_compliance": float(quality["avg_schema_score"])
            },
            "total_reviews": quality["total_reviews"],
            "last_reviewed": quality["last_reviewed"].isoformat() if quality["last_reviewed"] else None,
            "trend": quality["quality_trend"],
            "recent_reviews": [
                {
                    "rating": r["overall_rating"],
                    "reviewer": r["reviewer_name"],
                    "findings": r["findings"][:200] + "..." if len(r["findings"]) > 200 else r["findings"],
                    "date": r["submitted_at"].isoformat()
                }
                for r in recent_reviews
            ]
        }

@api.get("/data/package/{package_id}")
async def query_package_data(package_id: int, Authorization: Optional[str] = Header(None)):
    """Query data from a specific package"""
    claims = _auth(Authorization)
    if claims.get("scope") != "data.read.price":
        raise HTTPException(status_code=403, detail="Scope not allowed for this endpoint")
    
    async with db_pool.acquire() as conn:
        package = await conn.fetchrow("""
            SELECT p.*, s.id as supplier_id
            FROM data_packages p
            JOIN suppliers s ON p.supplier_id = s.id
            WHERE p.id = $1 AND p.status = 'active' AND s.status = 'active'
        """, package_id)
        
        if not package:
            raise HTTPException(status_code=404, detail="Package not found or inactive")
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(package["endpoint_url"])
        
        if r.status_code != 200:
            raise HTTPException(status_code=502, detail="Package endpoint error")
        
        data = r.json()
        
        price = float(package["price_per_query"])
        supplier_amt = round(price * SPLIT_SUPPLIER, 6)
        reviewer_pool = round(price * SPLIT_REVIEWER, 6)
        obius_amt = round(price * SPLIT_OBIUS, 6)
        
        await update_balances(supplier_amt, reviewer_pool, obius_amt, str(package["supplier_id"]))
        
        await conn.execute("""
            INSERT INTO query_history (package_id, agent_id, response_size, cost, trace_id)
            VALUES ($1, $2, $3, $4, $5)
        """, package_id, claims["sub"], len(str(data)), price, claims["trace_id"])
        
        receipt = {
            "trace_id": claims["trace_id"],
            "package_id": package_id,
            "package_name": package["name"],
            "ts": int(time.time()),
            "data": data,
            "cost": price,
            "payout": {"supplier": supplier_amt, "reviewer_pool": reviewer_pool, "obius": obius_amt}
        }
        return JSONResponse(receipt)

@api.get("/data/uploaded/{filename}")
async def serve_uploaded_data(
    filename: str,
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    Authorization: Optional[str] = Header(None)
):
    """Serve data from uploaded datasets"""
    claims = _auth(Authorization)
    if claims.get("scope") != "data.read.price":
        raise HTTPException(status_code=403, detail="Invalid scope")
    
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Dataset not found")
    
    try:
        df = pd.read_csv(file_path)
        total_rows = len(df)
        df_page = df.iloc[offset:offset+limit]
        json_data = df_page.to_dict(orient='records')
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading dataset: {str(e)}")
    
    async with db_pool.acquire() as conn:
        upload_info = await conn.fetchrow("""
            SELECT ud.*, dp.name as package_name, dp.price_per_query, dp.id as package_id
            FROM uploaded_datasets ud
            JOIN data_packages dp ON ud.package_id = dp.id
            WHERE ud.filename = $1
        """, filename)
        
        if not upload_info:
            raise HTTPException(status_code=404, detail="Package not found in database")
        
        price = float(upload_info["price_per_query"])
        supplier_amt = round(price * SPLIT_SUPPLIER, 6)
        reviewer_pool = round(price * SPLIT_REVIEWER, 6)
        obius_amt = round(price * SPLIT_OBIUS, 6)
        
        await update_balances(supplier_amt, reviewer_pool, obius_amt, str(upload_info["supplier_id"]))
        
        await conn.execute("""
            INSERT INTO query_history (package_id, agent_id, response_size, cost, trace_id)
            VALUES ($1, $2, $3, $4, $5)
        """, upload_info["package_id"], claims["sub"], len(str(json_data)), price, claims["trace_id"])
    
    receipt = {
        "trace_id": claims["trace_id"],
        "package_name": upload_info["package_name"],
        "filename": filename,
        "total_rows": total_rows,
        "returned_rows": len(json_data),
        "offset": offset,
        "limit": limit,
        "data": json_data,
        "cost": price,
        "payout": {"supplier": supplier_amt, "reviewer_pool": reviewer_pool, "obius": obius_amt}
    }
    
    return JSONResponse(receipt)

# Legacy Mint and Price Endpoints
@api.post("/mint")
def mint(req: MintReq):
    trace_id = str(uuid.uuid4())
    exp = int(time.time()) + 3600
    token = jwt.encode({
        "iss": "obius",
        "sub": req.agent_id,
        "scope": req.scope,
        "trace_id": trace_id,
        "price": PRICE,
        "splits": {"supplier": SPLIT_SUPPLIER, "reviewer": SPLIT_REVIEWER, "obius": SPLIT_OBIUS},
        "exp": exp,
        "jti": str(uuid.uuid4())
    }, SECRET, algorithm="HS256")
    return {"token": token, "trace_id": trace_id, "expires_in_s": 3600, "demo_credits": req.credits}

@api.get("/data/price")
async def get_price(pair: str = Query("BTCUSDT"), Authorization: Optional[str] = Header(None)):
    """Legacy price endpoint - queries the first crypto package"""
    claims = _auth(Authorization)
    if claims.get("scope") != "data.read.price":
        raise HTTPException(status_code=403, detail="Scope not allowed for this endpoint")
    
    async with db_pool.acquire() as conn:
        package = await conn.fetchrow("""
            SELECT p.*, s.id as supplier_id
            FROM data_packages p
            JOIN suppliers s ON p.supplier_id = s.id
            WHERE p.category = 'financial' AND p.tags && ARRAY['crypto', 'prices']
            AND p.status = 'active' AND s.status = 'active'
            ORDER BY p.created_at
            LIMIT 1
        """)
    
    if not package:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{COLLECTOR}/price", params={"pair": pair})
        if r.status_code != 200:
            raise HTTPException(status_code=502, detail="Collector error")
        data = r.json()
        
        await update_balances(
            round(PRICE * SPLIT_SUPPLIER, 6),
            round(PRICE * SPLIT_REVIEWER, 6), 
            round(PRICE * SPLIT_OBIUS, 6),
            "1"
        )
        
        receipt = {
            "trace_id": claims["trace_id"],
            "pair": pair,
            "ts": int(time.time()),
            "price": data["price"],
            "volume": data["volume"],
            "cost": PRICE,
            "payout": {
                "supplier": round(PRICE * SPLIT_SUPPLIER, 6),
                "reviewer_pool": round(PRICE * SPLIT_REVIEWER, 6),
                "obius": round(PRICE * SPLIT_OBIUS, 6)
            }
        }
        return JSONResponse(receipt)
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(package["endpoint_url"], params={"pair": pair})
    
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail="Package endpoint error")
    
    data = r.json()
    price = float(package["price_per_query"])
    supplier_amt = round(price * SPLIT_SUPPLIER, 6)
    reviewer_pool = round(price * SPLIT_REVIEWER, 6)
    obius_amt = round(price * SPLIT_OBIUS, 6)
    
    await update_balances(supplier_amt, reviewer_pool, obius_amt, str(package["supplier_id"]))
    
    receipt = {
        "trace_id": claims["trace_id"],
        "pair": pair,
        "ts": int(time.time()),
        "price": data["price"],
        "volume": data["volume"],
        "cost": price,
        "payout": {"supplier": supplier_amt, "reviewer_pool": reviewer_pool, "obius": obius_amt}
    }
    return JSONResponse(receipt)

# Balance and Payout Endpoints
@api.get("/balances")
async def get_balances():
    """Get all current balances - useful for monitoring"""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT user_type, user_id, balance_usd FROM balances ORDER BY user_type, user_id")
        return [{"type": row["user_type"], "id": row["user_id"], "balance": float(row["balance_usd"])} for row in rows]

@api.get("/balances/{user_type}/{user_id}")
async def get_balance(user_type: str, user_id: str):
    """Get balance for specific user"""
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT balance_usd, payout_threshold_usd FROM balances WHERE user_type = $1 AND user_id = $2",
            user_type, user_id
        )
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "user_type": user_type,
            "user_id": user_id,
            "balance": float(row["balance_usd"]),
            "payout_threshold": float(row["payout_threshold_usd"])
        }

@api.get("/payout-history")
async def get_payout_history():
    """Get recent payout history"""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT stellar_tx_hash, recipient_address, amount_usd, user_type, user_id, created_at
            FROM payout_history 
            ORDER BY created_at DESC 
            LIMIT 50
        """)
        return [
            {
                "tx_hash": row["stellar_tx_hash"],
                "recipient": row["recipient_address"],
                "amount": float(row["amount_usd"]),
                "user": f"{row['user_type']}/{row['user_id']}",
                "timestamp": row["created_at"].isoformat()
            }
            for row in rows
        ]

@api.get("/stellar/info")
async def stellar_info():
    """Get Stellar configuration info"""
    if not stellar_keypair:
        return {"status": "not_configured", "message": "Stellar not initialized"}
    
    return {
        "status": "configured",
        "public_key": stellar_keypair.public_key,
        "network": STELLAR_NETWORK,
        "payment_asset": "XLM (native)"
    }

# User Profile Endpoints
@api.get("/users/me")
async def get_unified_profile(x_api_key: Optional[str] = Header(None)):
    """Get unified user profile - works with usr_ keys only"""
    user = await authenticate_unified_user(x_api_key)
    
    async with db_pool.acquire() as conn:
        balance = 0
        stats = None
        package_count = 0
        
        # Get supplier info if user has supplier role
        if 'supplier' in user["roles"]:
            supplier_info = await conn.fetchrow("""
                SELECT 
                    COUNT(dp.id) as package_count,
                    b.balance_usd
                FROM users u
                LEFT JOIN data_packages dp ON u.id = dp.supplier_id
                LEFT JOIN balances b ON u.id::text = b.user_id AND b.user_type = 'supplier'
                WHERE u.id = $1
                GROUP BY b.balance_usd
            """, user["user_id"])
            
            if supplier_info:
                package_count = supplier_info["package_count"] or 0
                balance = float(supplier_info["balance_usd"] or 0)
        
        # Get reviewer info if user has reviewer role
        if 'reviewer' in user["roles"]:
            reviewer_info = await conn.fetchrow("""
                SELECT rs.*, b.balance_usd
                FROM reviewer_stats rs
                LEFT JOIN balances b ON rs.reviewer_id::text = b.user_id AND b.user_type = 'reviewer'
                WHERE rs.reviewer_id = $1
            """, user["user_id"])
            
            if reviewer_info:
                stats = {
                    "total_reviews": reviewer_info["total_reviews"] or 0,
                    "consensus_rate": float(reviewer_info["consensus_rate"] or 0),
                    "accuracy_score": float(reviewer_info["accuracy_score"] or 0),
                    "total_earned": float(reviewer_info["total_earned"] or 0),
                    "avg_review_time_minutes": reviewer_info["avg_review_time_minutes"] or 0
                }
                reviewer_balance = float(reviewer_info["balance_usd"] or 0)
                if reviewer_balance > balance:
                    balance = reviewer_balance
        
        user_type = "unified"
        if 'supplier' in user["roles"] and 'reviewer' in user["roles"]:
            user_type = "hybrid"
        elif 'supplier' in user["roles"]:
            user_type = "supplier"
        elif 'reviewer' in user["roles"]:
            user_type = "reviewer"
        
        return {
            "id": user["user_id"],
            "name": user["name"],
            "email": user["email"],
            "type": user_type,
            "stellar_address": user["stellar_address"],
            "roles": user["roles"],
            "balance": balance,
            "package_count": package_count if 'supplier' in user["roles"] else None,
            "stats": stats if 'reviewer' in user["roles"] else None,
            "api_key": user["api_key"]
        }

@api.get("/users/me/payout-history")
async def get_user_payout_history(x_api_key: Optional[str] = Header(None)):
    """Get user's payout history"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    async with db_pool.acquire() as conn:
        user_id = None
        user_type = None
        
        if x_api_key.startswith('rev_'):
            reviewer = await conn.fetchval("SELECT id FROM reviewers WHERE api_key = $1", x_api_key)
            if reviewer:
                user_id = str(reviewer)
                user_type = 'reviewer'
        elif x_api_key.startswith('sup_'):
            supplier = await conn.fetchval("SELECT id FROM suppliers WHERE api_key = $1", x_api_key)
            if supplier:
                user_id = str(supplier)
                user_type = 'supplier'
        elif x_api_key.startswith('usr_'):
            user_role = await conn.fetchrow("""
                SELECT user_id, role_type FROM user_roles WHERE api_key = $1 AND is_active = TRUE
            """, x_api_key)
            if user_role:
                user_id = str(user_role["user_id"])
                # Determine user type based on available roles
                roles = await conn.fetch("""
                    SELECT role_type FROM user_roles WHERE user_id = $1 AND is_active = TRUE
                """, user_role["user_id"])
                role_types = [r["role_type"] for r in roles]
                user_type = 'supplier' if 'supplier' in role_types else 'reviewer' if 'reviewer' in role_types else None
        
        if not user_id or not user_type:
            raise HTTPException(status_code=401, detail="Invalid API key")
            
        payouts = await conn.fetch("""
            SELECT stellar_tx_hash, amount_usd, created_at
            FROM payout_history
            WHERE user_type = $1 AND user_id = $2
            ORDER BY created_at DESC
            LIMIT 50
        """, user_type, user_id)
        
        return [
            {
                "tx_hash": p["stellar_tx_hash"],
                "amount": float(p["amount_usd"]),
                "date": p["created_at"].isoformat()
            } for p in payouts
        ]

@api.post("/users/me/update-payout-threshold")
async def update_payout_threshold(
    request: dict,
    x_api_key: Optional[str] = Header(None)
):
    """Update user's payout threshold"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    threshold = request.get("threshold")
    if not threshold or threshold < 0.01:
        raise HTTPException(status_code=400, detail="Invalid threshold")
    
    async with db_pool.acquire() as conn:
        user_id = None
        user_type = None
        
        if x_api_key.startswith('rev_'):
            reviewer = await conn.fetchval("SELECT id FROM reviewers WHERE api_key = $1", x_api_key)
            if reviewer:
                user_id = str(reviewer)
                user_type = 'reviewer'
        elif x_api_key.startswith('sup_'):
            supplier = await conn.fetchval("SELECT id FROM suppliers WHERE api_key = $1", x_api_key)
            if supplier:
                user_id = str(supplier)
                user_type = 'supplier'
        elif x_api_key.startswith('usr_'):
            user_role = await conn.fetchrow("""
                SELECT user_id, role_type FROM user_roles WHERE api_key = $1 AND is_active = TRUE
            """, x_api_key)
            if user_role:
                user_id = str(user_role["user_id"])
                roles = await conn.fetch("""
                    SELECT role_type FROM user_roles WHERE user_id = $1 AND is_active = TRUE
                """, user_role["user_id"])
                role_types = [r["role_type"] for r in roles]
                user_type = 'supplier' if 'supplier' in role_types else 'reviewer' if 'reviewer' in role_types else None
        
        if not user_id or not user_type:
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        await conn.execute("""
            UPDATE balances 
            SET payout_threshold_usd = $1
            WHERE user_type = $2 AND user_id = $3
        """, threshold, user_type, user_id)
        
        return {"success": True, "new_threshold": threshold}

# Admin Endpoints
@api.post("/admin/migrate")
async def run_migrations():
    """Run database migrations - ADMIN ONLY"""
    try:
        await add_unique_constraints()
        return {"status": "success", "message": "Database constraints applied"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Migration failed: {str(e)}")

@api.post("/admin/process-payouts")
async def trigger_payouts():
    """Manually trigger payout processing (admin endpoint)"""
    result = await process_payouts()
    return result

@api.post("/admin/create-review-task")
async def create_review_task(
    package_id: int,
    task_type: str,
    reward_pool: float = 0.05,
    required_reviews: int = 3
):
    """Admin endpoint to manually create review tasks"""
    async with db_pool.acquire() as conn:
        package = await conn.fetchrow("""
            SELECT * FROM data_packages WHERE id = $1
        """, package_id)
        
        if not package:
            raise HTTPException(status_code=404, detail="Package not found")
        
        reference_query = {
            "endpoint": package["endpoint_url"],
            "task_type": task_type,
            "package_category": package["category"]
        }
        
        task_id = await conn.fetchval("""
            INSERT INTO review_tasks (package_id, task_type, required_reviews, reward_pool_usd, reference_query, created_by)
            VALUES ($1, $2, $3, $4, $5, 'manual')
            RETURNING id
        """, package_id, task_type, required_reviews, reward_pool, json.dumps(reference_query))
        
        return {
            "task_id": task_id,
            "status": "created",
            "package": package["name"],
            "reward_pool": reward_pool
        }

@api.get("/admin/pii-logs")
async def get_pii_logs(limit: int = 50):
    """View PII detection logs"""
    async with db_pool.acquire() as conn:
        logs = await conn.fetch("""
            SELECT pdl.*, s.name as supplier_name
            FROM pii_detection_log pdl
            JOIN suppliers s ON pdl.supplier_id = s.id
            ORDER BY pdl.created_at DESC
            LIMIT $1
        """, limit)
        
        return [
            {
                "id": log["id"],
                "supplier": log["supplier_name"],
                "filename": log["filename"],
                "pii_type": log["pii_type"],
                "action": log["action_taken"],
                "findings_count": log["findings_count"],
                "blocked": log["blocked"],
                "timestamp": log["created_at"].isoformat()
            }
            for log in logs
        ]