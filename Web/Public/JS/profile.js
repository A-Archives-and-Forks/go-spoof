// Profile page functionality
document.addEventListener('DOMContentLoaded', function() {
    setupChangePassword();
    setupDeleteAccount();
});

// Change Password Functionality
function setupChangePassword() {
    const form = document.getElementById('change-password-form');
    const messageDiv = document.getElementById('password-message');
    
    if (form) {
        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const currentPassword = document.getElementById('current-password').value;
            const newPassword = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            
            // Clear previous messages
            messageDiv.textContent = '';
            messageDiv.className = 'status-message';
            
            // Validation
            if (newPassword !== confirmPassword) {
                showMessage('New passwords do not match', 'error');
                return;
            }
            
            if (newPassword.length < 12) {
                showMessage('New password must be at least 12 characters long', 'error');
                return;
            }
            
            // Check password requirements
            const hasUpperCase = /[A-Z]/.test(newPassword);
            const hasLowerCase = /[a-z]/.test(newPassword);
            const hasNumbers = /\d/.test(newPassword);
            const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword);
            
            if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
                showMessage('New password must contain uppercase, lowercase, number, and special character', 'error');
                return;
            }
            
            try {
                const response = await secureFetch('/api/change_password', {
                    method: 'POST',
                    body: JSON.stringify({
                        currentPassword,
                        newPassword
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showMessage('Password changed successfully!', 'success');
                    form.reset();
                } else {
                    showMessage(data.error || 'Failed to change password', 'error');
                }
            } catch (error) {
                showMessage('An error occurred. Please try again.', 'error');
            }
        });
    }
}

// Delete Account Functionality
function setupDeleteAccount() {
    const deleteBtn = document.getElementById('delete-account-btn');
    const modal = document.getElementById('delete-modal');
    const passwordInput = document.getElementById('delete-password');
    const confirmBtn = document.getElementById('confirm-delete');
    const cancelBtn = document.getElementById('cancel-delete');
    
    if (deleteBtn) {
        deleteBtn.addEventListener('click', function() {
            modal.classList.add('show');
            passwordInput.value = '';
            confirmBtn.disabled = true;
            passwordInput.focus();
        });
    }
    
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            confirmBtn.disabled = this.value.length === 0;
        });
        passwordInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && this.value.length > 0) {
                confirmBtn.click();
            }
        });
    }
    
    if (confirmBtn) {
        confirmBtn.addEventListener('click', async function() {
            const password = passwordInput.value;
            if (password.length > 0) {
                // Immediately clear localStorage and redirect for instant feedback
                localStorage.removeItem('userLoggedIn');
                localStorage.removeItem('username');
                
                // Close modal immediately
                modal.classList.remove('show');
                
                // Redirect immediately for instant visual feedback
                window.location.href = '/login';
                
                // Send deletion request in background (fire and forget)
                try {
                    const response = await secureFetch('/api/delete_user', {
                        method: 'POST',
                        body: JSON.stringify({ password })
                    });
                    
                    if (!response.ok) {
                        const data = await response.json();
                        console.error('Account deletion failed:', data.error);
                        // Note: User is already redirected, so we can't show an alert
                        // The session check will handle any issues
                    }
                } catch (error) {
                    console.error('Account deletion error:', error);
                    // Note: User is already redirected, so we can't show an alert
                    // The session check will handle any issues
                }
            }
        });
    }
    
    if (cancelBtn) {
        cancelBtn.addEventListener('click', function() {
            modal.classList.remove('show');
            passwordInput.value = '';
            confirmBtn.disabled = true;
        });
    }
    
    if (modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                modal.classList.remove('show');
                passwordInput.value = '';
                confirmBtn.disabled = true;
            }
        });
    }
}

// Helper function to show messages
function showMessage(message, type) {
    const messageDiv = document.getElementById('password-message');
    if (messageDiv) {
        messageDiv.textContent = message;
        messageDiv.className = `status-message ${type}`;
        
        // Auto-hide success messages after 5 seconds
        if (type === 'success') {
            setTimeout(() => {
                messageDiv.textContent = '';
                messageDiv.className = 'status-message';
            }, 5000);
        }
    }
} 