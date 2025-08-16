// Reset Password & Change Password Modal Functionality
document.addEventListener('DOMContentLoaded', function() {
  // Reset Password Modal Elements
  const resetPasswordBtn = document.getElementById('resetPasswordBtn');
  const resetPasswordModal = document.getElementById('resetPasswordModal');
  const closeResetModal = document.getElementById('closeResetModal');
  const cancelResetBtn = document.getElementById('cancelResetBtn');
  const verifyResetCodeBtn = document.getElementById('verifyResetCodeBtn');
  const progressMessage = document.getElementById('resetProgressMessage');
  const progressText = document.getElementById('resetProgressText');
  const codeInputs = document.querySelectorAll('.code-input');

  // Change Password Modal Elements
  const changePasswordModal = document.getElementById('changePasswordModal');
  const closeChangePasswordModal = document.getElementById('closeChangePasswordModal');
  const cancelChangePasswordBtn = document.getElementById('cancelChangePasswordBtn');
  const saveNewPasswordBtn = document.getElementById('saveNewPasswordBtn');
  const newPasswordInput = document.getElementById('newPassword');
  const confirmPasswordInput = document.getElementById('confirmPassword');
  const toggleNewPassword = document.getElementById('toggleNewPassword');
  const toggleConfirmPassword = document.getElementById('toggleConfirmPassword');
  const changePasswordProgressMessage = document.getElementById('changePasswordProgressMessage');
  const changePasswordProgressText = document.getElementById('changePasswordProgressText');

  // State variables
  let codeSent = false;
  let codeVerified = false;

  // ================================
  // RESET PASSWORD MODAL FUNCTIONS
  // ================================

  // Open reset modal
  resetPasswordBtn.addEventListener('click', function() {
    resetPasswordModal.classList.add('show');
    showProgressMessage('Ready to send verification code to your email', 'info');
  });

  // Close modal functions
  function closeResetModalFunc() {
    resetPasswordModal.classList.remove('show');
    resetForm();
  }

  closeResetModal.addEventListener('click', closeResetModalFunc);
  cancelResetBtn.addEventListener('click', closeResetModalFunc);

  // Close modal on window click (outside modal)
  window.addEventListener('click', function(event) {
    if (event.target === resetPasswordModal) {
      closeResetModalFunc();
    }
    if (event.target === changePasswordModal) {
      closeChangePasswordModalFunc();
    }
  });

  // Reset form function
  function resetForm() {
    codeInputs.forEach(input => input.value = '');
    progressMessage.style.display = 'none';
    verifyResetCodeBtn.disabled = false;
    verifyResetCodeBtn.innerHTML = '<i class="fas fa-paper-plane mr-2 text-white"></i><span class="text-white">Send Code</span>';
    codeSent = false;
    codeVerified = false;
  }

  // Progress message function
  function showProgressMessage(message, type) {
    progressMessage.style.display = 'block';
    progressMessage.className = `progress-message progress-${type}`;
    progressText.textContent = message;
    
    // Update icon based on type
    const icon = progressMessage.querySelector('i');
    if (type === 'info') {
      icon.className = 'fas fa-info-circle mr-2';
    } else if (type === 'success') {
      icon.className = 'fas fa-check-circle mr-2';
    } else if (type === 'error') {
      icon.className = 'fas fa-exclamation-circle mr-2';
    }
  }

  // Get CSRF token
  function getCSRFToken() {
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]');
    return csrfToken ? csrfToken.value : '';
  }

  // Send code / Verify code functionality
  verifyResetCodeBtn.addEventListener('click', function() {
    const code = Array.from(codeInputs).map(input => input.value).join('');
    
    if (!codeSent) {
      // Send verification code
      sendPasswordResetCode();
    } else {
      // Verify the code
      verifyPasswordResetCode(code);
    }
  });

  // Send password reset code
  function sendPasswordResetCode() {
    showProgressMessage('Sending verification code...', 'info');
    verifyResetCodeBtn.disabled = true;
    verifyResetCodeBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2 text-white"></i><span class="text-white">Sending...</span>';
    
    fetch('/members/ajax/send-password-reset-code/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRFToken': getCSRFToken(),
      },
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        showProgressMessage(data.message, 'success');
        verifyResetCodeBtn.innerHTML = '<i class="fas fa-check mr-2 text-white"></i><span class="text-white">Verify Code</span>';
        verifyResetCodeBtn.disabled = false;
        codeSent = true;
        // Focus first code input
        document.getElementById('code1').focus();
      } else {
        showProgressMessage(data.message, 'error');
        verifyResetCodeBtn.disabled = false;
        verifyResetCodeBtn.innerHTML = '<i class="fas fa-paper-plane mr-2 text-white"></i><span class="text-white">Send Code</span>';
      }
    })
    .catch(error => {
      console.error('Error:', error);
      showProgressMessage('Network error. Please try again.', 'error');
      verifyResetCodeBtn.disabled = false;
      verifyResetCodeBtn.innerHTML = '<i class="fas fa-paper-plane mr-2 text-white"></i><span class="text-white">Send Code</span>';
    });
  }

  // Verify password reset code
  function verifyPasswordResetCode(code) {
    if (code.length !== 6) {
      showProgressMessage('Please enter all 6 digits', 'error');
      return;
    }
    
    showProgressMessage('Verifying code...', 'info');
    verifyResetCodeBtn.disabled = true;
    verifyResetCodeBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2 text-white"></i><span class="text-white">Verifying...</span>';
    
    const formData = new FormData();
    formData.append('code', code);
    
    fetch('/members/ajax/verify-password-reset-code/', {
      method: 'POST',
      headers: {
        'X-CSRFToken': getCSRFToken(),
      },
      body: formData
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        showProgressMessage('Code verified! Opening password change form...', 'success');
        setTimeout(() => {
          closeResetModalFunc();
          openChangePasswordModal();
        }, 1500);
        codeVerified = true;
      } else {
        showProgressMessage(data.message, 'error');
        verifyResetCodeBtn.disabled = false;
        verifyResetCodeBtn.innerHTML = '<i class="fas fa-check mr-2 text-white"></i><span class="text-white">Verify Code</span>';
      }
    })
    .catch(error => {
      console.error('Error:', error);
      showProgressMessage('Network error. Please try again.', 'error');
      verifyResetCodeBtn.disabled = false;
      verifyResetCodeBtn.innerHTML = '<i class="fas fa-check mr-2 text-white"></i><span class="text-white">Verify Code</span>';
    });
  }

  // Code input handling
  codeInputs.forEach((input, index) => {
    input.addEventListener('input', function(e) {
      const value = e.target.value;
      
      // Only allow numbers
      if (!/^\d$/.test(value)) {
        e.target.value = '';
        return;
      }
      
      // Move to next input
      if (value && index < codeInputs.length - 1) {
        codeInputs[index + 1].focus();
      }
    });
    
    input.addEventListener('keydown', function(e) {
      // Handle backspace
      if (e.key === 'Backspace' && !input.value && index > 0) {
        codeInputs[index - 1].focus();
      }
    });
  });

  // ====================================
  // CHANGE PASSWORD MODAL FUNCTIONS
  // ====================================

  function openChangePasswordModal() {
    changePasswordModal.classList.add('show');
    showChangePasswordProgress('Ready to create your new password', 'info');
    newPasswordInput.focus();
  }

  function closeChangePasswordModalFunc() {
    changePasswordModal.classList.remove('show');
    resetChangePasswordForm();
  }

  closeChangePasswordModal.addEventListener('click', closeChangePasswordModalFunc);
  cancelChangePasswordBtn.addEventListener('click', closeChangePasswordModalFunc);

  function resetChangePasswordForm() {
    newPasswordInput.value = '';
    confirmPasswordInput.value = '';
    changePasswordProgressMessage.style.display = 'none';
    saveNewPasswordBtn.disabled = true;
    updatePasswordRequirements('');
    document.getElementById('passwordMatch').innerHTML = '';
    document.getElementById('passwordStrength').innerHTML = '';
  }

  function showChangePasswordProgress(message, type) {
    changePasswordProgressMessage.style.display = 'block';
    changePasswordProgressMessage.className = `progress-message progress-${type}`;
    changePasswordProgressText.textContent = message;
    
    // Update icon based on type
    const icon = changePasswordProgressMessage.querySelector('i');
    if (type === 'info') {
      icon.className = 'fas fa-info-circle mr-2';
    } else if (type === 'success') {
      icon.className = 'fas fa-check-circle mr-2';
    } else if (type === 'error') {
      icon.className = 'fas fa-exclamation-circle mr-2';
    }
  }

  // Password visibility toggles
  toggleNewPassword.addEventListener('click', function() {
    const input = newPasswordInput;
    const icon = this.querySelector('i');
    
    if (input.type === 'password') {
      input.type = 'text';
      icon.classList.remove('fa-eye');
      icon.classList.add('fa-eye-slash');
    } else {
      input.type = 'password';
      icon.classList.remove('fa-eye-slash');
      icon.classList.add('fa-eye');
    }
  });

  toggleConfirmPassword.addEventListener('click', function() {
    const input = confirmPasswordInput;
    const icon = this.querySelector('i');
    
    if (input.type === 'password') {
      input.type = 'text';
      icon.classList.remove('fa-eye');
      icon.classList.add('fa-eye-slash');
    } else {
      input.type = 'password';
      icon.classList.remove('fa-eye-slash');
      icon.classList.add('fa-eye');
    }
  });

  // Password validation
  function updatePasswordRequirements(password) {
    const requirements = {
      'req-length': password.length >= 8,
      'req-uppercase': /[A-Z]/.test(password),
      'req-lowercase': /[a-z]/.test(password),
      'req-number': /\d/.test(password)
    };

    Object.keys(requirements).forEach(reqId => {
      const element = document.getElementById(reqId);
      if (element) {
        const icon = element.querySelector('i');
        const isValid = requirements[reqId];
        
        if (isValid) {
          icon.className = 'fas fa-check text-green-500 mr-2 w-3';
          element.classList.add('text-green-600');
          element.classList.remove('text-gray-600');
        } else {
          icon.className = 'fas fa-times text-red-500 mr-2 w-3';
          element.classList.add('text-gray-600');
          element.classList.remove('text-green-600');
        }
      }
    });

    return Object.values(requirements).every(Boolean);
  }

  function updatePasswordStrength(password) {
    const strengthIndicator = document.getElementById('passwordStrength');
    if (!strengthIndicator) return;
    
    let strength = 0;
    let strengthText = '';
    let strengthColor = '';

    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength++;

    switch (strength) {
      case 0:
      case 1:
        strengthText = 'Very Weak';
        strengthColor = 'text-red-600';
        break;
      case 2:
        strengthText = 'Weak';
        strengthColor = 'text-red-500';
        break;
      case 3:
        strengthText = 'Fair';
        strengthColor = 'text-yellow-500';
        break;
      case 4:
        strengthText = 'Strong';
        strengthColor = 'text-green-500';
        break;
      case 5:
        strengthText = 'Very Strong';
        strengthColor = 'text-green-600';
        break;
    }

    strengthIndicator.innerHTML = password ? `Password strength: <span class="${strengthColor} font-medium">${strengthText}</span>` : '';
  }

  function checkPasswordMatch() {
    const matchIndicator = document.getElementById('passwordMatch');
    if (!matchIndicator) return false;
    
    const newPass = newPasswordInput.value;
    const confirmPass = confirmPasswordInput.value;

    if (confirmPass && newPass !== confirmPass) {
      matchIndicator.innerHTML = '<span class="text-red-500 font-medium">Passwords do not match</span>';
      return false;
    } else if (confirmPass && newPass === confirmPass) {
      matchIndicator.innerHTML = '<span class="text-green-500 font-medium">Passwords match</span>';
      return true;
    } else {
      matchIndicator.innerHTML = '';
      return false;
    }
  }

  // Password input event listeners
  newPasswordInput.addEventListener('input', function() {
    const password = this.value;
    const isValidPassword = updatePasswordRequirements(password);
    updatePasswordStrength(password);
    
    const passwordsMatch = checkPasswordMatch();
    saveNewPasswordBtn.disabled = !(isValidPassword && passwordsMatch && confirmPasswordInput.value);
  });

  confirmPasswordInput.addEventListener('input', function() {
    const passwordsMatch = checkPasswordMatch();
    const isValidPassword = updatePasswordRequirements(newPasswordInput.value);
    saveNewPasswordBtn.disabled = !(isValidPassword && passwordsMatch && newPasswordInput.value);
  });

  // Save new password
  saveNewPasswordBtn.addEventListener('click', function() {
    const newPassword = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (newPassword !== confirmPassword) {
      showChangePasswordProgress('Passwords do not match', 'error');
      return;
    }

    showChangePasswordProgress('Saving new password...', 'info');
    this.disabled = true;
    this.innerHTML = '<i class="fas fa-spinner fa-spin mr-2 text-white"></i><span class="text-white">Saving...</span>';

    const formData = new FormData();
    formData.append('new_password', newPassword);
    formData.append('confirm_password', confirmPassword);

    fetch('/members/ajax/change-password-with-reset/', {
      method: 'POST',
      headers: {
        'X-CSRFToken': getCSRFToken(),
      },
      body: formData
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        showChangePasswordProgress(data.message, 'success');
        setTimeout(() => {
          closeChangePasswordModalFunc();
          alert('Password changed successfully! You can now use your new password to log in.');
        }, 2000);
      } else {
        showChangePasswordProgress(data.message, 'error');
        this.disabled = false;
        this.innerHTML = '<i class="fas fa-save mr-2 text-white"></i><span class="text-white">Save New Password</span>';
      }
    })
    .catch(error => {
      console.error('Error:', error);
      showChangePasswordProgress('Network error. Please try again.', 'error');
      this.disabled = false;
      this.innerHTML = '<i class="fas fa-save mr-2 text-white"></i><span class="text-white">Save New Password</span>';
    });
  });

});
