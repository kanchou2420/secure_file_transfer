from flask import Blueprint
from flask_socketio import emit, join_room, leave_room
from database.models import db, ChatMessage, Transaction
from datetime import datetime
import logging

# Tạo logger
logger = logging.getLogger(__name__)
chat_bp = Blueprint('chat', __name__)

def init_socketio_events(socketio):
    """Initialize WebSocket events for chat and notifications"""
    
    @socketio.on('join')
    def handle_join(data):
        """Join user room for notifications"""
        try:
            user_id = data.get('user_id')
            if user_id:
                join_room(f'user_{user_id}')
                logger.info(f"User {user_id} joined notification room")
        except Exception as e:
            logger.error(f"Join error: {str(e)}")
            emit('error', {'message': str(e)})
    
    @socketio.on('join_transaction')
    def on_join_transaction(data):
        """Join transaction room for chat"""
        try:
            transaction_id = data['transaction_id']
            username = data['username']
            
            join_room(transaction_id)
            emit('user_joined', {
                'username': username,
                'message': f'{username} joined the conversation'
            }, room=transaction_id)
            logger.info(f"User {username} joined transaction {transaction_id}")
        except Exception as e:
            logger.error(f"Join transaction error: {str(e)}")
            emit('error', {'message': str(e)})
    
    @socketio.on('leave_transaction')
    def on_leave_transaction(data):
        """Leave transaction room"""
        try:
            transaction_id = data['transaction_id']
            username = data['username']
            
            leave_room(transaction_id)
            emit('user_left', {
                'username': username,
                'message': f'{username} left the conversation'
            }, room=transaction_id)
            logger.info(f"User {username} left transaction {transaction_id}")
        except Exception as e:
            logger.error(f"Leave transaction error: {str(e)}")
            emit('error', {'message': str(e)})
    
    @socketio.on('send_message')
    def on_send_message(data):
        """Send chat message"""
        try:
            transaction_id = data['transaction_id']
            sender_id = data['sender_id']
            message = data['message']
            
            # Save message to database
            chat_message = ChatMessage(
                transaction_id=transaction_id,
                sender_id=sender_id,
                message=message,
                timestamp=datetime.utcnow()
            )
            db.session.add(chat_message)
            db.session.commit()
            
            # Broadcast to room
            emit('new_message', {
                'id': chat_message.id,
                'sender_id': sender_id,
                'username': data['username'],
                'message': message,
                'timestamp': chat_message.timestamp.isoformat()
            }, room=transaction_id)
            logger.info(f"New message in transaction {transaction_id}")
            
        except Exception as e:
            logger.error(f"Send message error: {str(e)}")
            emit('error', {'message': str(e)})
    
    @socketio.on('file_transfer_progress')
    def on_file_transfer_progress(data):
        """Update file transfer progress"""
        try:
            transaction_id = data['transaction_id']
            progress = data['progress']
            status = data['status']
            
            emit('transfer_progress', {
                'progress': progress,
                'status': status
            }, room=transaction_id)
            logger.debug(f"Transfer progress: {progress}% in {transaction_id}")
        except Exception as e:
            logger.error(f"Progress update error: {str(e)}")
            emit('error', {'message': str(e)})
    
    @socketio.on('file_notification')
    def handle_file_notification(data):
        """Notify receiver about new file"""
        try:
            receiver_id = data.get('receiver_id')
            if receiver_id:
                emit('new_file_pending', data, room=f'user_{receiver_id}')
                logger.info(f"File notification sent to user {receiver_id}")
        except Exception as e:
            logger.error(f"File notification error: {str(e)}")