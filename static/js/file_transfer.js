// NOTE: Core file transfer functionality với crypto
class FileTransferHandler {
    constructor() {
        this.socket = io();
        this.currentTransaction = null;
        this.sessionKey = null;
        this.initializeEventListeners();
    }
    
    initializeEventListeners() {
        // Send file form
        document.getElementById('sendFileForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.sendFile();
        });
        
        // Socket events
        this.socket.on('transfer_progress', (data) => {
            this.updateProgress(data.progress, data.status);
        });
        
        this.socket.on('file_received', (data) => {
            this.handleFileReceived(data);
        });
        
        // Handle receive buttons
        document.querySelectorAll('.receive-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const transactionId = btn.dataset.transactionId;
                this.receiveFile(transactionId);
            });
        });
    }

    async sendFile() {
        const fileInput = document.getElementById('file');
        const receiverSelect = document.getElementById('receiver');
        const file = fileInput.files[0];
        
        if (!file || !receiverSelect.value) {
            alert('Please select a file and receiver');
            return;
        }
        
        try {
            // Create transaction
            this.currentTransaction = this.generateTransactionId();
            
            // Step 1: Handshake
            await this.performHandshake();
            
            // Step 2: Key exchange
            await this.performKeyExchange(receiverSelect.value);
            
            // Step 3: Encrypt and send file
            await this.encryptAndSendFile(file);
            
        } catch (error) {
            console.error('File transfer failed:', error);
            this.showError('File transfer failed: ' + error.message);
        }
    }
    
    async performHandshake() {
        // Send hello
        const response = await fetch('/api/handshake', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                transaction_id: this.currentTransaction,
                action: 'hello'
            })
        });
        
        if (!response.ok) throw new Error('Handshake failed');
        
        // Wait for ready (simulated)
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const readyResponse = await fetch('/api/handshake', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                transaction_id: this.currentTransaction,
                action: 'ready'
            })
        });
        
        if (!readyResponse.ok) throw new Error('Handshake ready failed');
        
        this.updateStatus('Handshake completed');
    }
    
    async performKeyExchange(receiverId) {
        // Generate session key
        this.sessionKey = this.generateSessionKey();
        
        // Get receiver's public key
        const userResponse = await fetch(`/api/user/${receiverId}`);
        const userData = await userResponse.json();
        
        // Encrypt session key with receiver's public key
        const encryptedSessionKey = await this.encryptWithRSA(
            btoa(Array.from(this.sessionKey).map(b => String.fromCharCode(b)).join('')),
            userData.public_key
        );
        
        // Create metadata signature
        const metadata = `${this.currentTransaction}_${Date.now()}`;
        const signature = await this.signWithRSA(metadata);
        
        // Send encrypted session key
        const response = await fetch('/api/auth_exchange', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                transaction_id: this.currentTransaction,
                encrypted_session_key: encryptedSessionKey,
                metadata_signature: signature
            })
        });
        
        if (!response.ok) throw new Error('Key exchange failed');
        
        this.updateStatus('Key exchange completed');
    }
    
    async encryptAndSendFile(file) {
        // Read file content
        const fileContent = await this.readFileContent(file);
        
        // Encrypt with AES-GCM
        const encrypted = await this.encryptWithAES(fileContent, this.sessionKey);
        
        // Calculate hash
        const nonce = atob(encrypted.nonce);
        const ciphertext = atob(encrypted.ciphertext);
        const tag = atob(encrypted.tag);
        const hash = await this.calculateSHA512(nonce + ciphertext + tag);
        
        // Sign the package
        const signature = await this.signWithRSA(hash);
        
        // Create file package
        const filePackage = {
            nonce: encrypted.nonce,
            cipher: encrypted.ciphertext,
            tag: encrypted.tag,
            hash: hash,
            sig: signature
        };
        
        // Send file package
        const response = await fetch('/api/send_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                transaction_id: this.currentTransaction,
                file_package: filePackage
            })
        });
        
        if (!response.ok) throw new Error('File send failed');
        
        this.updateStatus('File sent successfully');
    }

    async receiveFile(transactionId) {
    try {
        const response = await fetch('/receive_file', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrf_token')
            },
            body: JSON.stringify({ transaction_id: transactionId })
        });
        
        const data = await response.json();
        
        if (data.status === 'ACK') {
            this.showSuccess('File received successfully!');
            this.socket.emit('file_received', {
                transaction_id: transactionId,
                filename: data.filename
            });
        } else {
            this.showError(data.error || 'Failed to receive file');
        }
    } catch (error) {
        this.showError('Error receiving file: ' + error.message);
    }
}
    
    handleFileReceived(data) {
        this.showReceivedFile(data.filename, data.transaction_id);
    }
    
    showReceivedFile(filename, transactionId) {
        const filesList = document.getElementById('filesList');
        const fileItem = document.createElement('div');
        fileItem.className = 'list-group-item';
        fileItem.innerHTML = `
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <strong>${filename}</strong>
                    <div class="small">Transaction: ${transactionId}</div>
                </div>
                <a href="/download/${filename}" class="btn btn-sm btn-success">Download</a>
            </div>
        `;
        filesList.prepend(fileItem);
    }
    
    // Utility functions
    generateTransactionId() {
        return 'txn_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
    
    generateSessionKey() {
        return crypto.getRandomValues(new Uint8Array(32));
    }
    
    async readFileContent(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });
    }
    
    async encryptWithAES(data, key) {
        // NOTE: Browser implementation of AES-GCM
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
        
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            cryptoKey,
            dataBuffer
        );
        
        return {
            nonce: btoa(String.fromCharCode(...nonce)),
            ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
            tag: btoa(String.fromCharCode(...new Uint8Array(encrypted.slice(-16))))
        };
    }
    
    async calculateSHA512(data) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        const hashBuffer = await crypto.subtle.digest('SHA-512', dataBuffer);
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    
    async encryptWithRSA(data, publicKey) {
        // NOTE: Simplified RSA encryption for demo
        // In production, use proper RSA library
        return btoa(data + '_encrypted_with_' + publicKey.substr(0, 10));
    }
    
    async signWithRSA(data) {
        // NOTE: Simplified RSA signing for demo
        return btoa(data + '_signed');
    }
    
    updateStatus(message) {
        const statusDiv = document.getElementById('transferStatus');
        if (statusDiv) {
            statusDiv.innerHTML = `<div class="alert alert-info">${message}</div>`;
        }
    }
    
    updateProgress(progress, status) {
        const progressBar = document.querySelector('.progress-bar');
        if (progressBar) {
            progressBar.style.width = progress + '%';
            progressBar.textContent = status;
        }
    }
    
    showError(message) {
        const statusDiv = document.getElementById('transferStatus');
        if (statusDiv) {
            statusDiv.innerHTML = `<div class="alert alert-danger">${message}</div>`;
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new FileTransferHandler();
});
