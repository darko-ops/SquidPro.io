# Add to squidpro-api/app.py

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
api.state.limiter = limiter
api.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Apply rate limits to sensitive endpoints
@api.post("/mint")
@limiter.limit("10/minute")  # Limit token minting
async def mint_with_rate_limit(request: Request, req: SecureMintRequest):
    # existing mint logic
    pass

@api.post("/suppliers/register")
@limiter.limit("5/hour")  # Limit registration attempts
async def register_supplier_with_rate_limit(request: Request, supplier: SecureSupplierRegistration):
    # existing registration logic
    pass

@api.post("/suppliers/upload")
@limiter.limit("20/hour")  # Limit file uploads
async def upload_with_rate_limit(request: Request, ...):
    # existing upload logic
    pass
