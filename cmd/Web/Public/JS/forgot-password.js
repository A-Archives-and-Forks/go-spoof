// Simple fetch utility for localhost development (no CSRF needed)
function secureFetch(url, options = {}) {
  const headers = options.headers || {};
  headers['Content-Type'] = 'application/json';
  return fetch(url, { ...options, headers });
}

// Load CAPTCHA from server
async function loadCaptcha() {
  try {
    const response = await secureFetch('/api/captcha');
    const captcha = await response.json();
    
    document.getElementById('captchaQuestion').textContent = captcha.question;
    document.getElementById('captchaId').value = captcha.id;
  } catch (error) {
    console.error('Failed to load CAPTCHA:', error);
    document.getElementById('captchaQuestion').textContent = 'Error loading CAPTCHA';
  }
}

// Forgot password form handling
document.addEventListener('DOMContentLoaded', function() {
  const forgotPasswordForm = document.getElementById('forgotPasswordForm');
  const refreshCaptchaBtn = document.getElementById('refreshCaptcha');

  // Load initial CAPTCHA
  loadCaptcha();

  // Refresh CAPTCHA button
  if (refreshCaptchaBtn) {
    refreshCaptchaBtn.addEventListener('click', function() {
      loadCaptcha();
      document.getElementById('captchaAnswer').value = '';
    });
  }

  if (forgotPasswordForm) {
    forgotPasswordForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const submitBtn = this.querySelector('.login-btn');
      const btnText = submitBtn.querySelector('.btn-text');
      const btnLoading = submitBtn.querySelector('.btn-loading');
      const statusDiv = document.getElementById('forgotPasswordStatus');
      
      // Show loading state
      submitBtn.disabled = true;
      btnText.style.display = 'none';
      btnLoading.style.display = 'flex';
      statusDiv.style.display = 'none';
      
      // Get form data
      const formData = new FormData(this);
      const email = formData.get('email');
      const captchaAnswer = formData.get('captchaAnswer');
      const captchaId = formData.get('captchaId');
      
      try {
        const response = await secureFetch('/api/forgot_password', {
          method: 'POST',
          body: JSON.stringify({ 
            email, 
            captchaAnswer, 
            captchaId 
          })
        });
        
        const result = await response.json();
        
        if (response.ok) {
          statusDiv.className = 'status-message success';
          statusDiv.textContent = result.message;
          statusDiv.style.display = 'block';
          
          // Clear form and load new CAPTCHA
          this.reset();
          loadCaptcha();
        } else {
          statusDiv.className = 'status-message error';
          statusDiv.textContent = result.error || 'Failed to send reset link. Please try again.';
          statusDiv.style.display = 'block';
          
          // Load new CAPTCHA on error
          loadCaptcha();
        }
      } catch (error) {
        statusDiv.className = 'status-message error';
        statusDiv.textContent = 'Network error. Please check your connection.';
        statusDiv.style.display = 'block';
        
        // Load new CAPTCHA on error
        loadCaptcha();
      } finally {
        submitBtn.disabled = false;
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';
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