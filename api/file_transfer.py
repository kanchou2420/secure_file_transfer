from flask import Blueprint, request, jsonify, session, current_app
from flask_socketio import emit
from database.models import db, User, Transaction, TransactionLog
from crypto.rsa_handler import RSAHandler
from crypto.aes_handler import AESHandler
from crypto.hash_handler import HashHandler
from utils.logger import log_transaction
from utils.validators import sanitize_filename
from datetime import datetime
import base64
import os
import logging
import uuid
import hashlib
import json
import redis

# Tạo logger
logger = logging.getLogger(__name__)
transfer_bp = Blueprint('transfer', __name__)

# Redis for session keys (production)
r = redis.Redis(host='localhost', port=6379, db=0)

@transfer_bp.route('/handshake', methods=['POST'])
def handshake():
    """Step 1: Handshake initialization"""
    try:
        data = request.get_json()
        transaction_id = data.get('transaction_id', str(uuid.uuid4()))
        action = data.get('action')
        receiver_id = data.get('receiver_id')
        
        if not action or not receiver_id:
            return jsonify({'error': 'Missing action or receiver_id'}), 400
        
        # Log transaction
        log_transaction(transaction_id, f'handshake_{action}', 
                       f'Handshake {action} received', request.remote_addr)
        
        if action == 'hello':
            # Create new transaction
            new_transaction = Transaction(
                id=transaction_id,
                sender_id=session['user_id'],
                receiver_id=receiver_id,
                filename='',
                original_filename='',
                file_size=0,
                status='pending'
            )
            db.session.add(new_transaction)
            db.session.commit()
            
            return jsonify({
                'message': 'Handshake initiated',
                'transaction_id': transaction_id,
                'status': 'waiting_ready'
            })
            
        elif action == 'ready':
            # Verify existing transaction
            transaction = Transaction.query.get(transaction_id)
            if not transaction:
                return jsonify({'error': 'Transaction not found'}), 404
                
            if session['user_id'] != transaction.receiver_id:
                return jsonify({'error': 'Unauthorized'}), 403
                
            return jsonify({
                'message': 'Ready confirmed',
                'status': 'handshake_complete'
            })
            
        return jsonify({'error': 'Invalid action'}), 400
        
    except Exception as e:
        logger.error(f"Handshake error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@transfer_bp.route('/auth_exchange', methods=['POST'])
def auth_exchange():
    """Step 2: Authentication & Key Exchange"""
    try:
        data = request.get_json()
        transaction_id = data.get('transaction_id')
        encrypted_session_key = data.get('encrypted_session_key')
        metadata_signature = data.get('metadata_signature')
        
        if not transaction_id or not encrypted_session_key or not metadata_signature:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Verify transaction exists
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        # Verify sender
        sender_id = session['user_id']
        if sender_id != transaction.sender_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Verify metadata signature
        sender = User.query.get(sender_id)
        rsa_handler = RSAHandler()
        metadata = f"{transaction_id}{sender_id}{transaction.receiver_id}"
        
        if not rsa_handler.verify(metadata, metadata_signature, sender.public_key):
            return jsonify({'error': 'Metadata verification failed'}), 400
        
        # Store session key in Redis
        session_data = {
            'encrypted_key': encrypted_session_key,
            'sender_id': sender_id,
            'receiver_id': transaction.receiver_id
        }
        r.setex(f'session:{transaction_id}', 3600, json.dumps(session_data))
        
        log_transaction(transaction_id, 'auth_exchange', 
                       'Session key exchange completed', request.remote_addr)
        
        return jsonify({
            'message': 'Auth data processed',
            'status': 'auth_complete'
        })
        
    except Exception as e:
        logger.error(f"Auth exchange error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@transfer_bp.route('/send_file', methods=['POST'])
def send_file():
    """Step 3: Send encrypted file package"""
    try:
        data = request.get_json()
        transaction_id = data.get('transaction_id')
        file_package = data.get('file_package')
        
        if not transaction_id or not file_package:
            return jsonify({'error': 'Missing transaction_id or file_package'}), 400
        
        # Verify transaction
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        # Verify sender
        if session['user_id'] != transaction.sender_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Validate file package
        required_fields = ['filename', 'nonce', 'cipher', 'tag', 'hash', 'sig']
        if not all(field in file_package for field in required_fields):
            return jsonify({'error': 'Invalid file package'}), 400
        
        # Update transaction with file info
        transaction.original_filename = sanitize_filename(file_package['filename'])
        transaction.file_size = len(file_package['cipher'])
        db.session.commit()
        
        # Get existing session data
        session_data = r.get(f'session:{transaction_id}')
        if not session_data:
            return jsonify({'error': 'Session data not found'}), 404
            
        session_data = json.loads(session_data)
        session_data['file_package'] = file_package
        r.setex(f'session:{transaction_id}', 3600, json.dumps(session_data))
        
        # Notify receiver
        emit('file_notification', {
            'receiver_id': transaction.receiver_id,
            'transaction_id': transaction_id,
            'sender': session['username'],
            'filename': transaction.original_filename
        }, namespace='/', broadcast=True)
        
        log_transaction(transaction_id, 'file_send', 
                       'File package stored', request.remote_addr)
        
        return jsonify({
            'message': 'File package stored',
            'status': 'file_ready'
        })
        
    except Exception as e:
        logger.error(f"Send file error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@transfer_bp.route('/get_file_package/<transaction_id>', methods=['GET'])
def get_file_package(transaction_id):
    """Retrieve encrypted file package for receiver"""
    try:
        # Verify transaction
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        # Verify receiver
        if 'user_id' not in session or session['user_id'] != transaction.receiver_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get session data from Redis
        session_data = r.get(f'session:{transaction_id}')
        if not session_data or 'file_package' not in session_data:
            return jsonify({'error': 'File package not available'}), 404
            
        session_data = json.loads(session_data)
        return jsonify(session_data['file_package'])
        
    except Exception as e:
        logger.error(f"Get file package error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@transfer_bp.route('/confirm_receive', methods=['POST'])
def confirm_receive():
    """Receiver confirms readiness to receive"""
    try:
        data = request.get_json()
        transaction_id = data.get('transaction_id')
        
        if not transaction_id:
            return jsonify({'error': 'Transaction ID required'}), 400
        
        # Verify transaction
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        # Verify receiver
        if 'user_id' not in session or session['user_id'] != transaction.receiver_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Update status
        transaction.status = 'confirmed'
        db.session.commit()
        
        log_transaction(transaction_id, 'receive_confirmed', 
                       'Receiver confirmed readiness', request.remote_addr)
        
        return jsonify({'status': 'ACK'})
        
    except Exception as e:
        logger.error(f"Confirm receive error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@transfer_bp.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    """Step 4: Decrypt and save file"""
    try:
        data = request.get_json()
        transaction_id = data.get('transaction_id')
        
        if not transaction_id:
            return jsonify({'error': 'Transaction ID required'}), 400
        
        # Verify transaction
        transaction = Transaction.query.get(transaction_id)
        if not transaction or transaction.status != 'confirmed':
            return jsonify({'error': 'Transaction not ready'}), 400
        
        # Verify receiver
        if 'user_id' not in session or session['user_id'] != transaction.receiver_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get session data from Redis
        session_data = r.get(f'session:{transaction_id}')
        if not session_data:
            return jsonify({'error': 'Session data not found'}), 404
            
        session_data = json.loads(session_data)
        
        if 'encrypted_key' not in session_data or 'file_package' not in session_data:
            return jsonify({'error': 'Session key or file package missing'}), 404
        
        encrypted_session_key = session_data['encrypted_key']
        file_package = session_data['file_package']
        
        # Get receiver's private key
        receiver = User.query.get(session['user_id'])
        if not receiver or not receiver.private_key:
            return jsonify({'error': 'Receiver keys missing'}), 400
        
        # Giải mã private key của receiver
        master_key_str = current_app.config['MASTER_KEY']
        master_key = hashlib.sha256(master_key_str.encode()).digest()
        
        aes_handler = AESHandler()
        encrypted_private_key_data = {
            'ciphertext': receiver.private_key,
            'nonce': receiver.nonce,
            'tag': receiver.tag
        }
        
        try:
            receiver_private_key = aes_handler.decrypt(encrypted_private_key_data, master_key)
        except Exception as e:
            logger.error(f"Failed to decrypt receiver's private key: {str(e)}")
            return jsonify({'error': "Failed to decrypt receiver's private key"}), 500
        
        # Decrypt session key
        rsa_handler = RSAHandler()
        
        try:
            # Giải mã base64 trước
            encrypted_key_bytes = base64.b64decode(encrypted_session_key)
            session_key = rsa_handler.decrypt(encrypted_key_bytes, receiver_private_key)
            session_key = base64.b64decode(session_key) if isinstance(session_key, str) else session_key
        except Exception as e:
            logger.error(f"Session key decryption failed: {str(e)}")
            return jsonify({'error': 'Session key decryption failed'}), 400
        
        # Verify hash
        hash_handler = HashHandler()
        try:
            nonce_bytes = base64.b64decode(file_package['nonce'])
            cipher_bytes = base64.b64decode(file_package['cipher'])
            tag_bytes = base64.b64decode(file_package['tag'])
            
            calculated_hash = hash_handler.hash_file_packet(nonce_bytes, cipher_bytes, tag_bytes)
            
            if calculated_hash != file_package['hash']:
                log_transaction(transaction_id, 'hash_mismatch', 
                               'File hash verification failed', request.remote_addr)
                return jsonify({'error': 'File hash mismatch'}), 400
        except Exception as e:
            logger.error(f"Hash verification error: {str(e)}")
            return jsonify({'error': 'Invalid file data'}), 400
        
        # Decrypt file content
        aes_handler = AESHandler()
        try:
            decrypted = aes_handler.decrypt({
                'nonce': file_package['nonce'],
                'ciphertext': file_package['cipher'],
                'tag': file_package['tag']
            }, session_key)
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return jsonify({'error': 'File decryption failed'}), 400
        
        # Save file
        upload_dir = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)
        
        # Preserve file extension
        original_filename = file_package['filename']
        ext = original_filename.split('.')[-1] if '.' in original_filename else 'bin'
        filename = f"received_{transaction_id}.{ext}"
        filepath = os.path.join(upload_dir, filename)
        
        try:
            with open(filepath, 'wb') as f:
                if isinstance(decrypted, str):
                    f.write(decrypted.encode('utf-8'))
                else:
                    f.write(decrypted)
        except Exception as e:
            logger.error(f"File save error: {str(e)}")
            return jsonify({'error': 'Failed to save file'}), 500
        
        # Update transaction
        transaction.original_filename = original_filename
        transaction.filename = filename
        transaction.status = 'completed'
        transaction.completed_at = datetime.utcnow()
        db.session.commit()
        
        # Cleanup
        r.delete(f'session:{transaction_id}')
        
        log_transaction(transaction_id, 'file_saved', 
                       f'File saved as {filename}', request.remote_addr)
        
        return jsonify({
            'message': 'File decrypted and saved',
            'filename': filename,
            'original_filename': original_filename,
            'status': 'success'
        })
        
    except Exception as e:
        logger.error(f"Decrypt file error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@transfer_bp.route('/transactions', methods=['GET'])
def get_transactions():
    """Get user's file transactions"""
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
            
        user_id = session['user_id']
        transactions = Transaction.query.filter(
            (Transaction.sender_id == user_id) | 
            (Transaction.receiver_id == user_id)
        ).all()
        
        result = []
        for t in transactions:
            result.append({
                'id': t.id,
                'sender_id': t.sender_id,
                'sender_name': t.sender.username,
                'receiver_id': t.receiver_id,
                'receiver_name': t.receiver.username,
                'filename': t.filename,
                'original_filename': t.original_filename,
                'status': t.status,
                'created_at': t.created_at.isoformat(),
                'completed_at': t.completed_at.isoformat() if t.completed_at else None
            })
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Get transactions error: {str(e)}")
        return jsonify({'error': str(e)}), 500