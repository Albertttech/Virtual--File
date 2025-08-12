document.addEventListener("DOMContentLoaded", () => {
    // Elements
    const sendCodeBtn = document.getElementById('send-code-btn');
    const verifyBtn = document.getElementById('verify-btn');
    const messageDiv = document.getElementById('message');
    const codeInputs = document.querySelectorAll('input[type="text"][maxlength="1"]');
    const verificationSection = document.getElementById('verification-section');
    const userEmail = document.getElementById('user-email')?.value;
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]')?.value;

    // Return if no email or send button (page not in correct state)
    if (!userEmail || !sendCodeBtn) return;

    // Auto-focus and move between input fields
    codeInputs.forEach((input, index) => {
        input.addEventListener('input', (e) => {
            if (e.target.value.length === 1) {
                if (index < codeInputs.length - 1) {
                    codeInputs[index + 1].focus();
                } else if (verifyBtn) {
                    verifyBtn.focus();
                }
            }
        });
        
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && e.target.value === '' && index > 0) {
                codeInputs[index - 1].focus();
            }
        });
    });

    // Event Listeners
    sendCodeBtn.addEventListener('click', sendVerificationCode);
    if (verifyBtn) {
        verifyBtn.addEventListener('click', verifyCode);
    }

    // Functions
    function sendVerificationCode(event) {
        if (event) event.preventDefault();
        
        // UI State
        sendCodeBtn.disabled = true;
        sendCodeBtn.textContent = 'Sending...';
        sendCodeBtn.classList.add('opacity-75');
        clearMessage();

        fetch('{% url "members:send_email_code" %}', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({email: userEmail})
        })
        .then(handleResponse)
        .then(data => {
            if (data.ok) {
                showMessage(data.message, 'success');
                if (verificationSection) {
                    verificationSection.style.display = 'block';
                }
                startCountdownTimer(60); // 60 second cooldown
            } else {
                throw new Error(data.error || 'Failed to send code');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showMessage(error.message || 'Failed to send code. Please try again.', 'error');
            sendCodeBtn.disabled = false;
            sendCodeBtn.textContent = 'Send Verification Code';
            sendCodeBtn.classList.remove('opacity-75');
        });
    }

    function verifyCode() {
        const code = Array.from(codeInputs).map(input => input.value.trim()).join('');
        
        if (code.length !== 6) {
            showMessage('Please enter the full 6-digit code', 'error');
            return;
        }

        // UI State
        if (verifyBtn) {
            verifyBtn.disabled = true;
            verifyBtn.textContent = 'Verifying...';
            verifyBtn.classList.add('opacity-75');
        }
        clearMessage();
        showMessage('Verifying code...', 'info');

        fetch('{% url "members:verify_email_code" %}', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                email: userEmail,
                code: code
            })
        })
        .then(handleResponse)
        .then(data => {
            if (data.success) {
                showMessage(data.message, 'success');
                if (data.redirect_url) {
                    refreshSessionAndRedirect(data.redirect_url);
                }
            } else {
                throw new Error(data.error || 'Verification failed');
            }
        })
        .catch(error => {
            console.error('Verification error:', error);
            showMessage(error.message || 'Verification failed. Please try again.', 'error');
        })
        .finally(() => {
            if (verifyBtn) {
                verifyBtn.disabled = false;
                verifyBtn.textContent = 'Verify Code';
                verifyBtn.classList.remove('opacity-75');
            }
        });
    }

    function refreshSessionAndRedirect(url) {
        fetch('{% url "members:refresh_session" %}', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        })
        .then(() => {
            window.location.href = url;
        });
    }

    function startCountdownTimer(seconds) {
        let remaining = seconds;
        const timer = setInterval(() => {
            remaining--;
            sendCodeBtn.textContent = `Resend Code (${remaining}s)`;
            
            if (remaining <= 0) {
                clearInterval(timer);
                sendCodeBtn.disabled = false;
                sendCodeBtn.textContent = 'Send Verification Code';
                sendCodeBtn.classList.remove('opacity-75');
            }
        }, 1000);
    }

    function handleResponse(response) {
        if (!response.ok) {
            return response.json().then(err => { 
                throw new Error(err.error || 'Request failed'); 
            });
        }
        return response.json();
    }

    function showMessage(message, type) {
        messageDiv.textContent = message;
        messageDiv.className = 'mt-4 text-center font-medium';
        messageDiv.classList.add(
            type === 'success' ? 'text-green-500' :
            type === 'error' ? 'text-red-500' :
            'text-blue-500'
        );
        messageDiv.style.display = 'block';
    }

    function clearMessage() {
        messageDiv.textContent = '';
        messageDiv.className = 'mt-4 text-center';
        messageDiv.style.display = 'none';
    }
});