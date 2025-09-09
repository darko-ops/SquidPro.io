# Add to squidpro-api/app.py

from pydantic import validator, Field
import re

class SecureSupplierRegistration(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, regex="^[a-zA-Z0-9\\s\\-\\.]+$")
    email: str = Field(..., regex="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")
    stellar_address: str = Field(..., min_length=56, max_length=56, regex="^G[A-Z2-7]{55}$")
    
    @validator('name')
    def validate_name(cls, v):
        # Prevent SQL injection in name field
        dangerous_chars = ["'", '"', ';', '--', '/*', '*/', 'DROP', 'SELECT', 'INSERT', 'UPDATE', 'DELETE']
        for char in dangerous_chars:
            if char.lower() in v.lower():
                raise ValueError(f"Invalid character or keyword in name: {char}")
        return v

class SecureMintRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=50, regex="^[a-zA-Z0-9_\\-]+$")
    credits: float = Field(..., ge=0.0, le=1000.0)  # Limit credits to reasonable range
    scope: str = Field(default="data.read.price", regex="^[a-zA-Z0-9\\.]+$")
