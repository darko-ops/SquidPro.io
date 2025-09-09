# Enhanced file upload security

import magic
import hashlib
from pathlib import Path

ALLOWED_MIME_TYPES = ['text/csv', 'text/plain']
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

async def secure_file_upload(file: UploadFile, supplier_id: int):
    """Secure file upload with comprehensive validation"""
    
    # 1. Validate file extension
    if not file.filename.lower().endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files allowed")
    
    # 2. Read and validate file size
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large")
    
    # 3. Validate MIME type using python-magic
    mime_type = magic.from_buffer(content, mime=True)
    if mime_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid file type: {mime_type}")
    
    # 4. Generate secure filename
    file_hash = hashlib.sha256(content).hexdigest()[:16]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    secure_filename = f"{supplier_id}_{timestamp}_{file_hash}.csv"
    
    # 5. Validate file path doesn't contain traversal
    if '..' in secure_filename or '/' in secure_filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    # 6. Scan content for malicious patterns
    content_str = content.decode('utf-8', errors='ignore')
    malicious_patterns = ['<script', 'javascript:', 'eval(', 'exec(', '<?php']
    for pattern in malicious_patterns:
        if pattern.lower() in content_str.lower():
            raise HTTPException(status_code=400, detail="Malicious content detected")
    
    return content, secure_filename
