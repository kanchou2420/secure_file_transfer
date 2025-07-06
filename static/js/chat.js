// NOTE: Real-time chat functionality
class ChatHandler {
    constructor() {
        this.socket = io();
        this.currentTransaction = null;
        this.currentUser = null;
        this.initializeChat();
    }
    
    initializeChat() {
        // Get current user info
        fetch('/api/me')
            .then(response => response.json())
            .then(data => {
                this.currentUser = data;
            });
        
        // Chat input event
        document.getElementById('chatInput')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendMessage();
            }
        });
        
        document.getElementById('sendChatBtn')?.addEventListener('click', () => {
            this.sendMessage();
        });
        
        // Socket events
        this.socket.on('new_message', (data) => {
            this.displayMessage(data);
        });
        
        this.socket.on('user_joined', (data) => {
            this.displaySystemMessage(data.message);
        });
        
        this.socket.on('user_left', (data) => {
            this.displaySystemMessage(data.message);
        });
        // File received notification
        this.socket.on('file_received_notification', (data) => {
            this.displaySystemMessage(`File ${data.filename} received successfully`);
        });
    }
    
    joinTransactionChat(transactionId) {
        this.currentTransaction = transactionId;
        this.socket.emit('join_transaction', {
            transaction_id: transactionId,
            username: this.currentUser.username
        });
    }
    
    sendMessage() {
        const input = document.getElementById('chatInput');
        const message = input.value.trim();
        
        if (!message || !this.currentTransaction) return;
        
        this.socket.emit('send_message', {
            transaction_id: this.currentTransaction,
            sender_id: this.currentUser.id,
            username: this.currentUser.username,
            message: message
        });
        
        input.value = '';
    }
    
    displayMessage(data) {
        const messagesDiv = document.getElementById('chatMessages');
        if (!messagesDiv) return;
        
        const messageElement = document.createElement('div');
        messageElement.className = 'mb-2';
        
        const isOwnMessage = data.sender_id === this.currentUser.id;
        const messageClass = isOwnMessage ? 'bg-primary text-white' : 'bg-light';
        
        messageElement.innerHTML = `
            <div class="p-2 rounded ${messageClass}">
                <small class="fw-bold">${data.username}:</small>
                <div>${data.message}</div>
                <small class="text-muted">${new Date(data.timestamp).toLocaleTimeString()}</small>
            </div>
        `;
        
        messagesDiv.appendChild(messageElement);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }
    
    displaySystemMessage(message) {
        const messagesDiv = document.getElementById('chatMessages');
        if (!messagesDiv) return;
        
        const messageElement = document.createElement('div');
        messageElement.className = 'mb-2 text-center';
        messageElement.innerHTML = `
            <small class="text-muted fst-italic">${message}</small>
        `;
        
        messagesDiv.appendChild(messageElement);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.chatHandler = new ChatHandler();
});