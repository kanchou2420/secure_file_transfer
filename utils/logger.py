from database.models import db, TransactionLog
from datetime import datetime

def log_transaction(transaction_id, action, details, ip_address):
    """Log transaction action"""
    try:
        log = TransactionLog(
            transaction_id=transaction_id,
            action=action,
            details=details,
            ip_address=ip_address,
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Logging error: {e}")
        db.session.rollback()

def init_logger(app):
    """Initialize logging configuration"""
    import logging
    from logging.handlers import RotatingFileHandler
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create logger
    logger = logging.getLogger('secure_transfer')
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        'secure_transfer.log',
        maxBytes=1024 * 1024 * 10,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    app.logger = logger