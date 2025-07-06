# NOTE: Input validation utilities
import re
from typing import Dict, Any

def validate_login_data(data: Dict[str, Any]) -> bool:
    """
    Validate login data
    NOTE: Kiểm tra username và password format
    """
    if not isinstance(data, dict):
        return False
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return False
    
    # Username validation: alphanumeric, 3-20 characters
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False
    
    # Password validation: at least 6 characters
    if len(password) < 6:
        return False
    
    return True

def validate_file_upload(file_data: Dict[str, Any]) -> bool:
    """
    Validate file upload data
    NOTE: Kiểm tra file size và type
    """
    if not isinstance(file_data, dict):
        return False
    
    filename = file_data.get('filename')
    file_size = file_data.get('file_size')
    
    if not filename or not file_size:
        return False
    
    # File size limit: 16MB
    if file_size > 16 * 1024 * 1024:
        return False
    
    # Allowed file extensions
    allowed_extensions = {'.txt', '.pdf', '.doc', '.docx', '.jpg', '.png', '.zip'}
    file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
    
    if f'.{file_ext}' not in allowed_extensions:
        return False
    
    return True

def validate_transaction_id(transaction_id: str) -> bool:
    """
    Validate transaction ID format
    NOTE: Format: txn_timestamp_random
    """
    if not isinstance(transaction_id, str):
        return False
    
    # Transaction ID pattern: txn_numbers_alphanumeric
    pattern = r'^txn_\d+_[a-zA-Z0-9]+$'
    return bool(re.match(pattern, transaction_id))

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal
    NOTE: Loại bỏ các ký tự nguy hiểm
    """
    if not filename:
        return 'unknown'
    
    # Remove path separators and dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)
    filename = filename.replace('..', '')
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename or 'unknown'

def validate_chat_message(message: str) -> bool:
    """
    Validate chat message
    NOTE: Kiểm tra độ dài và nội dung
    """
    if not isinstance(message, str):
        return False
    
    # Message length limit: 1000 characters
    if len(message) > 1000:
        return False
    
    # No empty messages
    if not message.strip():
        return False


    
    return True

def validate_transaction_id(transaction_id):
    """Validate transaction ID format"""
    return bool(re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', transaction_id))

def validate_file_package(package):
    """Validate file package structure"""
    required = ['filename', 'nonce', 'cipher', 'tag', 'hash', 'sig']
    return all(key in package for key in required)