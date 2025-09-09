# Ensure all database queries use parameterized statements

# GOOD - Parameterized query
async def safe_user_lookup(conn, user_id: int):
    return await conn.fetchrow("SELECT * FROM suppliers WHERE id = $1", user_id)

# BAD - String interpolation (vulnerable)
# async def unsafe_user_lookup(conn, user_id):
#     return await conn.fetchrow(f"SELECT * FROM suppliers WHERE id = {user_id}")

# Add input sanitization wrapper
async def execute_safe_query(conn, query: str, *params):
    """Execute query with additional safety checks"""
    # Check for dangerous SQL keywords in params
    dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'ALTER', 'CREATE', 'EXEC']
    
    for param in params:
        if isinstance(param, str):
            for keyword in dangerous_keywords:
                if keyword.upper() in param.upper():
                    raise ValueError(f"Potentially dangerous SQL keyword detected: {keyword}")
    
    return await conn.fetchrow(query, *params)
