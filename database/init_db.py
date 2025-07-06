from database.models import db, User
from crypto.rsa_handler import RSAHandler
from crypto.aes_handler import AESHandler
from werkzeug.security import generate_password_hash
import os
import hashlib

def init_database(app):
    """
    Initialize database and create default accounts
    """
    with app.app_context():
        db.create_all()
        
        # Create default accounts if not exist
        if not User.query.filter_by(username='admin').first():
            rsa_handler = RSAHandler()
            aes_handler = AESHandler()
            master_key_str = os.environ.get('MASTER_KEY', 'default-master-key-change-me')
            
            # Tạo key AES có độ dài phù hợp (32 bytes) từ chuỗi bất kỳ
            master_key = hashlib.sha256(master_key_str.encode()).digest()
            
            # Admin account
            admin_keys = rsa_handler.generate_keypair()
            encrypted_private_key = aes_handler.encrypt(admin_keys['private'], master_key)
            
            admin = User(
                username='admin',
                role='admin',
                public_key=admin_keys['public'],
                private_key=encrypted_private_key['ciphertext'],
                nonce=encrypted_private_key['nonce'],
                tag=encrypted_private_key['tag']
            )
            admin.set_password('admin123')
            
            # User accounts
            user1_keys = rsa_handler.generate_keypair()
            encrypted_private_key = aes_handler.encrypt(user1_keys['private'], master_key)
            
            user1 = User(
                username='skibidi',
                role='user',
                public_key=user1_keys['public'],
                private_key=encrypted_private_key['ciphertext'],
                nonce=encrypted_private_key['nonce'],
                tag=encrypted_private_key['tag']
            )
            user1.set_password('skibidi123')
            
            user2_keys = rsa_handler.generate_keypair()
            encrypted_private_key = aes_handler.encrypt(user2_keys['private'], master_key)
            
            user2 = User(
                username='pumpkin',
                role='user',
                public_key=user2_keys['public'],
                private_key=encrypted_private_key['ciphertext'],
                nonce=encrypted_private_key['nonce'],
                tag=encrypted_private_key['tag']
            )
            user2.set_password('pumpkin123')
            
            db.session.add_all([admin, user1, user2])
            db.session.commit()