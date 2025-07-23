// Simple fetch utility for localhost development (no CSRF needed)
function secureFetch(url, options = {}) {
  const headers = options.headers || {};
  headers['Content-Type'] = 'application/json';
  return fetch(url, { ...options, headers });
}

// Password validation function
function validatePassword(password) {
  const requirements = {
    length: password.length >= 12,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /\d/.test(password),
    special: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)
  };
  
  return requirements;
}

// Update password requirements display
function updatePasswordRequirements(password) {
  const requirements = validatePassword(password);
  const requirementsContainer = document.querySelector('.password-requirements');
  
  if (!requirementsContainer) return;
  
  Object.keys(requirements).forEach(requirement => {
    const requirementElement = requirementsContainer.querySelector(`[data-requirement="${requirement}"]`);
    const iconElement = requirementElement.querySelector('.requirement-icon');
    
    if (requirements[requirement]) {
      requirementElement.classList.remove('invalid');
      requirementElement.classList.add('valid');
      iconElement.textContent = '✓';
    } else {
      requirementElement.classList.remove('valid');
      requirementElement.classList.add('invalid');
      iconElement.textContent = '✕';
    }
  });
}

// Reset password form handling
document.addEventListener('DOMContentLoaded', function() {
  const resetPasswordForm = document.getElementById('resetPasswordForm');

  if (resetPasswordForm) {
    resetPasswordForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const submitBtn = this.querySelector('.login-btn');
      const btnText = submitBtn.querySelector('.btn-text');
      const btnLoading = submitBtn.querySelector('.btn-loading');
      const statusDiv = document.getElementById('resetPasswordStatus');
      
      // Get form data
      const formData = new FormData(this);
      const token = document.getElementById('token').value;
      const newPassword = formData.get('newPassword');
      const confirmPassword = formData.get('confirmPassword');
      
      // Show loading state first
      submitBtn.disabled = true;
      btnText.style.display = 'none';
      btnLoading.style.display = 'flex';
      statusDiv.style.display = 'none';
      
      // Check if passwords match
      if (newPassword !== confirmPassword) {
        statusDiv.className = 'status-message error';
        statusDiv.textContent = 'Passwords do not match.';
        statusDiv.style.display = 'block';
        // Reset loading state
        submitBtn.disabled = false;
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';
        return;
      }
      
      // Check password requirements
      const passwordRequirements = validatePassword(newPassword);
      const allRequirementsMet = Object.values(passwordRequirements).every(met => met);
      
      if (!allRequirementsMet) {
        statusDiv.className = 'status-message error';
        statusDiv.textContent = 'Password does not meet all requirements.';
        statusDiv.style.display = 'block';
        // Reset loading state
        submitBtn.disabled = false;
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';
        return;
      }
      
      try {
        const response = await secureFetch('/api/reset_password', {
          method: 'POST',
          body: JSON.stringify({ token, newPassword })
        });
        
        const result = await response.json();
        
        if (response.ok) {
          statusDiv.className = 'status-message success';
          statusDiv.textContent = result.message + ' Redirecting to login...';
          statusDiv.style.display = 'block';
          
          setTimeout(() => {
            window.location.href = '/login';
          }, 2000);
        } else {
          statusDiv.className = 'status-message error';
          statusDiv.textContent = result.error || 'Failed to reset password. Please try again.';
          statusDiv.style.display = 'block';
        }
      } catch (error) {
        statusDiv.className = 'status-message error';
        statusDiv.textContent = 'Network error. Please check your connection.';
        statusDiv.style.display = 'block';
      } finally {
        submitBtn.disabled = false;
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';
      }
    });
  }

  // Password input event listener
  const newPasswordInput = document.getElementById('newPassword');
  if (newPasswordInput) {
    newPasswordInput.addEventListener('input', function() {
      updatePasswordRequirements(this.value);
    });
    
    // Show requirements on focus
    newPasswordInput.addEventListener('focus', function() {
      const requirementsContainer = document.querySelector('.password-requirements');
      if (requirementsContainer) {
        requirementsContainer.style.maxHeight = '150px';
        requirementsContainer.style.opacity = '1';
      }
    });
    
    // Hide requirements on blur (if password is valid or empty)
    newPasswordInput.addEventListener('blur', function() {
      const requirementsContainer = document.querySelector('.password-requirements');
      if (requirementsContainer) {
        const passwordRequirements = validatePassword(this.value);
        const allRequirementsMet = Object.values(passwordRequirements).every(met => met);
        
        // Hide if all requirements are met or password is empty
        if (allRequirementsMet || this.value === '') {
          requirementsContainer.style.maxHeight = '0';
          requirementsContainer.style.opacity = '0';
        }
      }
    });
  }

  // Combined event listeners for inputs
  document.querySelectorAll('.form-group input').forEach(input => {
    // Focus effects
    input.addEventListener('focus', function() {
      this.parentElement.style.transform = 'scale(1.02)';
    });
    
    input.addEventListener('blur', function() {
      this.parentElement.style.transform = 'scale(1)';
    });
    
    // Enter key support
    input.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        const form = this.closest('form');
        if (form) {
          form.dispatchEvent(new Event('submit'));
        }
      }
    });
  });
}); 