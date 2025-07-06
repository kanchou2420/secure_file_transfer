from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    public_key = db.Column(db.Text)
    private_key = db.Column(db.Text)
    nonce = db.Column(db.Text)
    tag = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=True)  # Thêm trường xác thực
    
    # Relationships
    sent_transactions = db.relationship(
        'Transaction', 
        foreign_keys='Transaction.sender_id',
        backref='sender',
        lazy='dynamic'
    )
    
    received_transactions = db.relationship(
        'Transaction', 
        foreign_keys='Transaction.receiver_id',
        backref='receiver',
        lazy='dynamic'
    )
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def sent_files_count(self):
        return self.sent_transactions.count()
    
    @property
    def received_files_count(self):
        return self.received_transactions.count()
    
    @property
    def storage_used(self):
        sent_size = db.session.query(db.func.sum(Transaction.file_size)).filter(
            Transaction.sender_id == self.id
        ).scalar() or 0
        
        received_size = db.session.query(db.func.sum(Transaction.file_size)).filter(
            Transaction.receiver_id == self.id
        ).scalar() or 0
        
        return sent_size + received_size

class Transaction(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255))
    file_size = db.Column(db.Integer)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

class TransactionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), db.ForeignKey('transaction.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    
    transaction = db.relationship('Transaction', backref='logs')

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), db.ForeignKey('transaction.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    sender = db.relationship('User')
    transaction = db.relationship('Transaction')