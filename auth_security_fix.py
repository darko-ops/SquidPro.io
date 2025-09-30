# Add to squidpro-api/app.py

import secrets
import hashlib
from datetime import datetime, timedelta

def generate_secure_api_key(user_type: str) -> str:
    """Generate cryptographically secure API keys"""
    timestamp = int(datetime.now().timestamp())
    random_bytes = secrets.token_urlsafe(32)
    return f"{user_type}_{timestamp}_{random_bytes}"

def hash_api_key(api_key: str) -> str:
    """Hash API keys for secure storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()

async def authenticate_with_timing_protection(api_key: str, user_type: str):
    """Authenticate with protection against timing attacks"""
    import time
    start_time = time.time()
    
    # Always perform the same operations regardless of key validity
    hashed_key = hash_api_key(api_key)
    
    async with db_pool.acquire() as conn:
        if user_type == "supplier":
            user = await conn.fetchrow(
                "SELECT id, name, status FROM suppliers WHERE api_key_hash = $1 AND status = 'active'",
                hashed_key
            )
        elif user_type == "reviewer":
            user = await conn.fetchrow(
                "SELECT id, name, reputation_level FROM reviewers WHERE api_key_hash = $1",
                hashed_key
            )
        else:
            user = None
    
    # Ensure consistent timing
    elapsed = time.time() - start_time
    if elapsed < 0.1:  # Minimum 100ms delay
        time.sleep(0.1 - elapsed)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return user
