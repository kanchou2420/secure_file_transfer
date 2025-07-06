// NOTE: General UI functionality và common functions
class MainHandler {
    constructor() {
        this.currentUser = null;
        this.initializeMain();
    }
    
    initializeMain() {
        // Load current user info
        this.loadCurrentUser();
        
        // Initialize navigation
        this.initializeNavigation();
        
        // Initialize dashboard
        this.initializeDashboard();
        
        // Initialize auto-refresh
        this.initializeAutoRefresh();
    }
    
    async loadCurrentUser() {
        try {
            const response = await fetch('/api/me');
            if (response.ok) {
                this.currentUser = await response.json();
                this.updateUserInfo();
            }
        } catch (error) {
            console.error('Failed to load user info:', error);
        }
    }
    
    updateUserInfo() {
        // Update user display in navbar
        const userDisplay = document.getElementById('userDisplay');
        if (userDisplay && this.currentUser) {
            userDisplay.textContent = `Welcome, ${this.currentUser.username}`;
        }
        
        // Update role badge
        const roleBadge = document.getElementById('roleBadge');
        if (roleBadge && this.currentUser) {
            roleBadge.textContent = this.currentUser.role;
            roleBadge.className = `badge ${this.currentUser.role === 'admin' ? 'bg-danger' : 'bg-info'}`;
        }
    }
    
    initializeNavigation() {
        // Sender navigation
        document.getElementById('senderNav')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/sender';
        });
        
        // Receiver navigation
        document.getElementById('receiverNav')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/receiver';
        });
        
        // Admin navigation
        document.getElementById('adminNav')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/admin';
        });
        
        // Dashboard navigation
        document.getElementById('dashboardNav')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/';
        });
        
        // Logout
        document.getElementById('logoutBtn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.logout();
        });
    }
    
    initializeDashboard() {
        // Load user transactions
        this.loadUserTransactions();
        
        // Load user statistics
        this.loadUserStats();
        
        // Initialize quick actions
        this.initializeQuickActions();
    }
    
    async loadUserTransactions() {
        try {
            const response = await fetch('/api/transactions');
            if (response.ok) {
                const transactions = await response.json();
                this.displayUserTransactions(transactions);
            }
        } catch (error) {
            console.error('Failed to load transactions:', error);
        }
    }
    
    displayUserTransactions(transactions) {
        const transactionsTable = document.getElementById('userTransactionsTable');
        if (!transactionsTable) return;
        
        transactionsTable.innerHTML = '';
        
        transactions.slice(0, 5).forEach(transaction => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${transaction.id.substr(0, 8)}...</td>
                <td>${transaction.sender}</td>
                <td>${transaction.receiver}</td>
                <td>${transaction.filename}</td>
                <td>
                    <span class="badge bg-${this.getStatusColor(transaction.status)}">
                        ${transaction.status}
                    </span>
                </td>
                <td>${new Date(transaction.created_at).toLocaleString()}</td>
            `;
            transactionsTable.appendChild(row);
        });
    }
    
    async loadUserStats() {
        try {
            const response = await fetch('/api/transactions');
            if (response.ok) {
                const transactions = await response.json();
                this.displayUserStats(transactions);
            }
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }
    
    displayUserStats(transactions) {
        const totalTransactions = transactions.length;
        const successfulTransactions = transactions.filter(t => t.status === 'success').length;
        const pendingTransactions = transactions.filter(t => t.status === 'pending').length;
        const failedTransactions = transactions.filter(t => t.status === 'failed').length;
        
        // Update stats cards
        document.getElementById('totalTransactions').textContent = totalTransactions;
        document.getElementById('successfulTransactions').textContent = successfulTransactions;
        document.getElementById('pendingTransactions').textContent = pendingTransactions;
        document.getElementById('failedTransactions').textContent = failedTransactions;
        
        // Update success rate
        const successRate = totalTransactions > 0 ? 
            Math.round((successfulTransactions / totalTransactions) * 100) : 0;
        document.getElementById('successRate').textContent = `${successRate}%`;
    }
    
    initializeQuickActions() {
        // Quick send file
        document.getElementById('quickSendBtn')?.addEventListener('click', () => {
            window.location.href = '/sender';
        });
        
        // Quick receive file
        document.getElementById('quickReceiveBtn')?.addEventListener('click', () => {
            window.location.href = '/receiver';
        });
        
        // View all transactions
        document.getElementById('viewAllTransactionsBtn')?.addEventListener('click', () => {
            this.toggleTransactionHistory();
        });
        
        // Refresh data
        document.getElementById('refreshDataBtn')?.addEventListener('click', () => {
            this.refreshDashboard();
        });
    }
    
    toggleTransactionHistory() {
        const historySection = document.getElementById('transactionHistory');
        if (historySection) {
            historySection.style.display = 
                historySection.style.display === 'none' ? 'block' : 'none';
        }
    }
    
    refreshDashboard() {
        // Show loading indicator
        this.showLoading();
        
        // Reload all data
        Promise.all([
            this.loadCurrentUser(),
            this.loadUserTransactions(),
            this.loadUserStats()
        ]).then(() => {
            this.hideLoading();
            this.showNotification('Dashboard refreshed successfully', 'success');
        }).catch(error => {
            this.hideLoading();
            this.showNotification('Failed to refresh dashboard', 'error');
            console.error('Refresh failed:', error);
        });
    }
    
    initializeAutoRefresh() {
        // Auto-refresh every 30 seconds
        setInterval(() => {
            this.loadUserTransactions();
            this.loadUserStats();
        }, 30000);
    }
    
    async logout() {
        try {
            const response = await fetch('/api/logout', {
                method: 'POST'
            });
            
            if (response.ok) {
                window.location.href = '/login';
            }
        } catch (error) {
            console.error('Logout failed:', error);
        }
    }
    
    // Utility functions
    getStatusColor(status) {
        switch(status) {
            case 'success': return 'success';
            case 'failed': return 'danger';
            case 'pending': return 'warning';
            default: return 'secondary';
        }
    }
    
    showLoading() {
        const loadingOverlay = document.getElementById('loadingOverlay');
        if (loadingOverlay) {
            loadingOverlay.style.display = 'block';
        }
    }
    
    hideLoading() {
        const loadingOverlay = document.getElementById('loadingOverlay');
        if (loadingOverlay) {
            loadingOverlay.style.display = 'none';
        }
    }
    
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = 'top: 20px; right: 20px; z-index: 1050; min-width: 300px;';
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // Add to body
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);
    }
    
    // Format file size
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Format timestamp
    formatTimestamp(timestamp) {
        return new Date(timestamp).toLocaleString();
    }
    
    // Validate file type
    validateFileType(file) {
        const allowedTypes = ['text/plain', 'application/pdf', 'image/jpeg', 'image/png'];
        return allowedTypes.includes(file.type);
    }
    
    // Validate file size
    validateFileSize(file) {
        const maxSize = 16 * 1024 * 1024; // 16MB
        return file.size <= maxSize;
    }
    
    // Copy to clipboard
    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.showNotification('Copied to clipboard', 'success');
        }).catch(err => {
            console.error('Failed to copy:', err);
            this.showNotification('Failed to copy to clipboard', 'error');
        });
    }
    
    // Download file
    downloadFile(filename, content) {
        const element = document.createElement('a');
        element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
        element.setAttribute('download', filename);
        element.style.display = 'none';
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);
    }
    
    // Check network status
    checkNetworkStatus() {
        return navigator.onLine;
    }
    
    // Initialize network status monitoring
    initializeNetworkMonitoring() {
        window.addEventListener('online', () => {
            this.showNotification('Connection restored', 'success');
        });
        
        window.addEventListener('offline', () => {
            this.showNotification('Connection lost', 'warning');
        });
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.mainHandler = new MainHandler();
});

// Global utility functions
window.utils = {
    formatFileSize: (bytes) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    
    formatTimestamp: (timestamp) => {
        return new Date(timestamp).toLocaleString();
    },
    
    generateId: () => {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    },
    
    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
};