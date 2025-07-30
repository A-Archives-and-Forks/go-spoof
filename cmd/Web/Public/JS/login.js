// Simple fetch utility for localhost development (no CSRF needed)
function secureFetch(url, options = {}) {
  const headers = options.headers || {};
  headers['Content-Type'] = 'application/json';
  return fetch(url, { ...options, headers });
}

// Login form handling
document.addEventListener('DOMContentLoaded', function() {
  const loginForm = document.getElementById('loginForm');
  const signupForm = document.getElementById('signupForm');



  // Login form event listener
  if (loginForm) {
    loginForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const submitBtn = this.querySelector('.login-btn');
      const btnText = submitBtn.querySelector('.btn-text');
      const btnLoading = submitBtn.querySelector('.btn-loading');
      const statusDiv = document.getElementById('loginStatus');
      
      // Show loading state
      submitBtn.disabled = true;
      btnText.style.display = 'none';
      btnLoading.style.display = 'flex';
      statusDiv.style.display = 'none';
      
      // Get form data
      const formData = new FormData(this);
      const usernameOrEmail = formData.get('usernameOrEmail');
      const password = formData.get('password');
      
      // Validate input
      if (!usernameOrEmail.trim()) {
        statusDiv.className = 'status-message error';
        statusDiv.textContent = 'Please enter your username or email.';
        statusDiv.style.display = 'block';
        submitBtn.disabled = false;
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';
        return;
      }
      
      if (!password.trim()) {
        statusDiv.className = 'status-message error';
        statusDiv.textContent = 'Please enter your password.';
        statusDiv.style.display = 'block';
        submitBtn.disabled = false;
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';
        return;
      }
      
      // Determine if input is email or username
      const isEmail = usernameOrEmail.includes('@');
      const loginData = isEmail 
        ? { email: usernameOrEmail, password: password }
        : { username: usernameOrEmail, password: password };
      
      try {
        const response = await secureFetch('/api/login_user', {
          method: 'POST',
          body: JSON.stringify(loginData)
        });
        
        const result = await response.json();
        
        if (response.ok) {
          statusDiv.className = 'status-message success';
          statusDiv.textContent = result.message || 'Login successful! Redirecting...';
          statusDiv.style.display = 'block';
          
          setTimeout(() => {
            window.location.reload(true); // Force full reload to refresh CSRF token
          }, 1500);
        } else {
          statusDiv.className = 'status-message error';
          statusDiv.textContent = result.error || 'Login failed. Please try again.';
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

  // Signup form event listener
  if (signupForm) {
    signupForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const submitBtn = this.querySelector('.signup-btn');
      const btnText = submitBtn.querySelector('.btn-text');
      const btnLoading = submitBtn.querySelector('.btn-loading');
      const statusDiv = document.getElementById('signupStatus');
      
      // Get form data
      const formData = new FormData(this);
      const password = formData.get('password');
      const confirmPassword = formData.get('confirmPassword');
      
      // Check if passwords match
      if (password !== confirmPassword) {
        statusDiv.className = 'status-message error';
        statusDiv.textContent = 'Passwords do not match.';
        statusDiv.style.display = 'block';
        return;
      }
      
      // Check password requirements
      const passwordRequirements = validatePassword(password);
      const allRequirementsMet = Object.values(passwordRequirements).every(met => met);
      
      if (!allRequirementsMet) {
        statusDiv.className = 'status-message error';
        statusDiv.textContent = 'Password does not meet all requirements.';
        statusDiv.style.display = 'block';
        return;
      }
      
      // Show loading state
      submitBtn.disabled = true;
      btnText.style.display = 'none';
      btnLoading.style.display = 'flex';
      statusDiv.style.display = 'none';
      
      // Prepare signup data
      const signupData = {
        username: formData.get('username'),
        email: formData.get('email'),
        password: password
      };
      
      try {
        const response = await secureFetch('/api/create_user', {
          method: 'POST',
          body: JSON.stringify(signupData)
        });
        
        const result = await response.json();
        
        if (response.ok) {
          statusDiv.className = 'status-message success';
          statusDiv.textContent = 'Account created successfully! Logging you in...';
          statusDiv.style.display = 'block';
          
          // Auto-login with the same credentials
          try {
            const loginResponse = await secureFetch('/api/login_user', {
              method: 'POST',
              body: JSON.stringify({
                username: signupData.username,
                password: signupData.password
              })
            });
            
            const loginResult = await loginResponse.json();
            
            if (loginResponse.ok) {
              statusDiv.textContent = 'Account created and logged in successfully! Redirecting...';
              setTimeout(() => {
                window.location.reload(true); // Force full reload to refresh CSRF token
              }, 1500);
            } else {
              // Auto-login failed, redirect to login page
              statusDiv.textContent = 'Account created! Please login to continue.';
              setTimeout(() => {
                window.location.href = '/login';
              }, 2000);
            }
          } catch (loginError) {
            // Auto-login failed due to network error, redirect to login page
            statusDiv.textContent = 'Account created! Please login to continue.';
            setTimeout(() => {
              window.location.href = '/login';
            }, 2000);
          }
        } else {
          statusDiv.className = 'status-message error';
          statusDiv.textContent = result.error || 'Error creating account. Please try again.';
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
  
  // Password input event listener
  const passwordInput = document.getElementById('password');
  if (passwordInput) {
    passwordInput.addEventListener('input', function() {
      updatePasswordRequirements(this.value);
    });
    
    // Show requirements on focus
    passwordInput.addEventListener('focus', function() {
      const requirementsContainer = document.querySelector('.password-requirements');
      if (requirementsContainer) {
        requirementsContainer.style.maxHeight = '150px';
        requirementsContainer.style.opacity = '1';
      }
    });
    
    // Hide requirements on blur (if password is valid or empty)
    passwordInput.addEventListener('blur', function() {
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
  
  // Combined event listeners for inputs (works for both forms)
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
