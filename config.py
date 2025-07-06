import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///secure_transfer.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    MASTER_KEY = os.environ.get('MASTER_KEY', 'change-me-to-a-secret-key')
    
    # Security settings
    SESSION_COOKIE_SECURE = True  # NOTE: Chỉ dùng khi có HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # RSA settings
    RSA_KEY_SIZE = 1024
    AES_KEY_SIZE = 32  # 256-bit
    
    # Default users
    DEFAULT_USERS = [
        {'username': 'admin', 'password': 'admin123', 'role': 'admin'},
        {'username': 'skibidi', 'password': 'skibidi123', 'role': 'user'},
        {'username': 'pumpkin', 'password': 'pumpkin123', 'role': 'user'}
    ]