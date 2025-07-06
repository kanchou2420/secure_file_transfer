from flask import Blueprint, request, jsonify, session
from database.models import db, User
from utils.validators import validate_login_data
from crypto.aes_handler import AESHandler
import os
import logging
import hashlib

# Tạo logger
logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        # Validate input
        if not validate_login_data(data):
            return jsonify({'error': 'Invalid input data'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Store session
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'role': user.role,
                    'public_key': user.public_key
                }
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    try:
        session.clear()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/me', methods=['GET'])
def get_current_user():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        user = User.query.get(session['user_id'])
        
        # Giải mã private key nếu cần (chỉ debug)
        decrypted_private_key = None
        if user.private_key:
            try:
                master_key_str = os.environ.get('MASTER_KEY')
                if master_key_str:
                    # Tạo key AES có độ dài phù hợp
                    master_key = hashlib.sha256(master_key_str.encode()).digest()
                    aes = AESHandler()
                    encrypted_data = {
                        'ciphertext': user.private_key,
                        'nonce': user.nonce,
                        'tag': user.tag
                    }
                    decrypted_private_key = aes.decrypt(encrypted_data, master_key)
            except Exception as e:
                logger.warning(f"Private key decryption warning: {str(e)}")
        
        return jsonify({
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'public_key': user.public_key,
            'private_key': decrypted_private_key  # Chỉ để debug
        })
    except Exception as e:
        logger.error(f"Get user error: {str(e)}")
        return jsonify({'error': str(e)}), 500