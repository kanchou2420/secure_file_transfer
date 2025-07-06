from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory, flash
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect, generate_csrf
from database.models import db, User, Transaction, TransactionLog, ChatMessage
from database.init_db import init_database
from api.auth import auth_bp
from api.file_transfer import transfer_bp
from api.chat import chat_bp, init_socketio_events
from utils.logger import init_logger
from crypto.rsa_handler import RSAHandler
from datetime import datetime, timedelta
import humanize
import os
import logging
import re
import uuid
from werkzeug.utils import secure_filename
from sqlalchemy import func

# Create Flask app
app = Flask(__name__)
app.config.from_object('config.Config')

# Custom filters
def format_datetime(value, format='%H:%M, %d/%m/%Y'):
    if value is None:
        return ""
    return value.strftime(format)

def filesizeformat(value):
    return humanize.naturalsize(value)

# Register filters with Jinja2
app.jinja_env.filters['format_datetime'] = format_datetime
app.jinja_env.filters['filesizeformat'] = filesizeformat

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")
csrf = CSRFProtect(app)

# Context processor to inject current year
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/api')
app.register_blueprint(transfer_bp, url_prefix='/api')
app.register_blueprint(chat_bp, url_prefix='/api')

# Initialize WebSocket events
init_socketio_events(socketio)

# Initialize logger
init_logger(app)

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Middleware to set CSRF token in cookie
@app.after_request
def set_csrf_cookie(response):
    response.set_cookie('csrf_token', generate_csrf())
    return response

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Lấy thông tin thống kê
    total_files_sent = Transaction.query.filter_by(sender_id=user.id).count()
    total_files_received = Transaction.query.filter_by(receiver_id=user.id).count()
    
    # Lấy các giao dịch gần đây
    recent_transactions = Transaction.query.filter(
        (Transaction.sender_id == user.id) | 
        (Transaction.receiver_id == user.id)
    ).order_by(Transaction.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                           user=user,
                           total_files_sent=total_files_sent,
                           total_files_received=total_files_received,
                           recent_transactions=recent_transactions)

@app.route('/sender')
def sender():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Lấy người dùng hiện tại
    current_user = User.query.get(session['user_id'])
    
    # Lấy tất cả người dùng ngoại trừ người dùng hiện tại
    users = User.query.filter(User.id != session['user_id']).all()
    
    return render_template('sender.html', 
                           users=users, 
                           user=current_user)

@app.route('/receiver')
def receiver():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Get pending transactions
    pending_transactions = Transaction.query.filter_by(
        receiver_id=user_id, 
        status='pending'
    ).all()
    
    # Get completed transactions
    completed_transactions = Transaction.query.filter(
        Transaction.receiver_id == user_id,
        Transaction.status != 'pending'
    ).all()
    
    # Prepare list of received files
    received_files = []
    for txn in completed_transactions:
        if txn.status == 'completed' and txn.filename:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], txn.filename)
            if os.path.exists(filepath):
                received_files.append({
                    'transaction_id': txn.id,
                    'filename': txn.filename,
                    'original_filename': txn.original_filename,
                    'sender': txn.sender.username,
                    'timestamp': txn.completed_at
                })
    
    return render_template('receiver.html', 
                          pending=pending_transactions,
                          received_files=received_files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password:
            return render_template('register.html', error='Username and password are required')
        
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        
        # Generate RSA keys for new user
        rsa_handler = RSAHandler()
        keys = rsa_handler.generate_keypair()
        
        # Create new user
        new_user = User(
            username=username,
            public_key=keys['public'],
            private_key=keys['private'],
            role='user',
            is_verified=True  # Mặc định xác thực
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        return render_template('register.html', success='Registration successful! Please login.')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/send_file', methods=['POST'])
def send_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Lấy dữ liệu từ form
    file = request.files.get('file')
    receiver_id = request.form.get('receiver_id')
    encrypt = 'encrypt' in request.form
    self_destruct = 'self_destruct' in request.form
    password_protect = 'password_protect' in request.form
    message = request.form.get('message', '')
    
    # Validate
    if not file or not receiver_id:
        flash('Vui lòng chọn file và người nhận', 'danger')
        return redirect(url_for('sender'))
    
    # Kiểm tra người nhận/sender
    receiver = User.query.get(receiver_id)
    if not receiver:
        flash('Người nhận không hợp lệ', 'danger')
        return redirect(url_for('sender'))
    
    # Get file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    # Tạo transaction
    transaction = Transaction(
        sender_id=session['user_id'],
        receiver_id=receiver_id,
        original_filename=file.filename,
        file_size=file_size,
        status='pending'
    )
    db.session.add(transaction)
    db.session.commit()
    
    # Lưu file (tạm thời)
    upload_folder = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    filename = f"pending_{transaction.id}_{secure_filename(file.filename)}"
    file.save(os.path.join(upload_folder, filename))
    
    # TODO: Thực hiện mã hóa và chuyển file thực tế ở đây
    
    flash('File đã được gửi thành công!', 'success')
    return redirect(url_for('index'))

@app.route('/receive_file', methods=['POST'])
def handle_receive_file():
    """Endpoint for receiver to confirm file reception"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    data = request.get_json()
    transaction_id = data.get('transaction_id')
    if not transaction_id:
        return jsonify({'error': 'Transaction ID required'}), 400
    
    # Verify transaction exists
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    
    # Verify receiver
    if session['user_id'] != transaction.receiver_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Update status
    transaction.status = 'confirmed'
    db.session.commit()
    
    # Return ACK with filename
    return jsonify({
        'status': 'ACK',
        'filename': transaction.filename,
        'original_filename': transaction.original_filename
    })

@app.route('/download/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Verify user access
    try:
        # Extract transaction ID from filename
        match = re.search(r'received_([a-f0-9-]+)\.', filename)
        if not match:
            return "Invalid filename", 400
            
        transaction_id = match.group(1)
        transaction = Transaction.query.get(transaction_id)
        
        if not transaction:
            return "Transaction not found", 404
        
        user_id = session['user_id']
        if transaction.receiver_id != user_id and transaction.sender_id != user_id:
            return "Unauthorized access", 403
    except Exception as e:
        app.logger.error(f"Error verifying file access: {str(e)}")
        return "Invalid file", 400
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        return "File not found", 404
    
    # Use original filename for download
    download_name = transaction.original_filename if transaction else filename
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 
        filename, 
        as_attachment=True,
        download_name=download_name
    )

@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    return render_template('admin.html')

# API Endpoints
@app.route('/api/me')
def get_current_user():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'role': user.role,
        'public_key': user.public_key,
        'sent_files': user.sent_files_count,
        'received_files': user.received_files_count,
        'storage_used': user.storage_used
    })

@app.route('/api/users')
def get_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    current_user_id = session['user_id']
    users = User.query.filter(User.id != current_user_id).all()
    
    users_list = []
    for user in users:
        users_list.append({
            'id': user.id,
            'username': user.username,
            'public_key': user.public_key,
            'is_verified': user.is_verified
        })
    
    return jsonify(users_list)

@app.route('/api/transactions/recent')
def get_recent_transactions():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user_id) | 
        (Transaction.receiver_id == user_id)
    ).order_by(Transaction.created_at.desc()).limit(5).all()
    
    transactions_list = []
    for txn in transactions:
        # Get receiver name
        receiver_name = txn.receiver.username if txn.receiver else "Unknown"
        
        transactions_list.append({
            'id': txn.id,
            'filename': txn.filename,
            'original_filename': txn.original_filename,
            'status': txn.status,
            'created_at': txn.created_at.isoformat(),
            'file_size': txn.file_size,
            'receiver_name': receiver_name
        })
    
    return jsonify(transactions_list)

@app.route('/api/user/<int:user_id>')
def get_user(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'username': user.username,
        'public_key': user.public_key
    })

@app.route('/api/logs')
def get_logs():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    logs = TransactionLog.query.order_by(TransactionLog.timestamp.desc()).limit(100).all()
    result = []
    for log in logs:
        result.append({
            'timestamp': log.timestamp.isoformat(),
            'transaction_id': log.transaction_id,
            'action': log.action,
            'details': log.details,
            'ip_address': log.ip_address
        })
    
    return jsonify(result)

@app.route('/api/chat/<transaction_id>')
def get_chat_history(transaction_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Verify access
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    
    user_id = session['user_id']
    if transaction.sender_id != user_id and transaction.receiver_id != user_id:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    messages = ChatMessage.query.filter_by(
        transaction_id=transaction_id
    ).order_by(ChatMessage.timestamp.asc()).all()
    
    result = []
    for msg in messages:
        result.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'username': msg.sender.username,
            'message': msg.message,
            'timestamp': msg.timestamp.isoformat()
        })
    
    return jsonify(result)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f'Server Error: {e}')
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Initialize database
    with app.app_context():
        db.create_all()
        init_database(app)
    
    # Run app
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)