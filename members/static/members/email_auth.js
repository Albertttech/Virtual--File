document.addEventListener("DOMContentLoaded", () => {
    const sendCodeBtn = document.getElementById('send-code-btn');
    const messageDiv = document.getElementById('message');
    const codeInputs = document.querySelectorAll('input[type="text"][maxlength="1"]');
    
    if (!sendCodeBtn) return;

    // Auto-focus and move between input fields
    codeInputs.forEach((input, index) => {
        input.addEventListener('input', (e) => {
            if (e.target.value.length === 1) {
                if (index < codeInputs.length - 1) {
                    codeInputs[index + 1].focus();
                } else {
                    verifyCode();
                }
            }
        });
        
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && e.target.value === '') {
                if (index > 0) {
                    codeInputs[index - 1].focus();
                }
            }
        });
    });

    sendCodeBtn.addEventListener('click', sendVerificationCode);

    function sendVerificationCode(event) {
        if (event) event.preventDefault();
        sendCodeBtn.disabled = true;
        let countdown = 60;
        clearMessage();
        
        const email = document.getElementById('user-email')?.value;
        
        if (!email) {
            showMessage('No email provided', 'error');
            sendCodeBtn.disabled = false;
            return;
        }

        fetch('/send_email_code/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({email: email})
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw err; });
            }
            return response.json();
        })
        .then(data => {
            if (data.ok) {
                showMessage(data.message, 'success');
            } else {
                throw data;
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showMessage(error.error || 'Failed to send code. Please try again.', 'error');
        })
        .finally(() => {
            startCountdownTimer(countdown);
        });
    }

    function verifyCode() {
        const email = document.getElementById('user-email')?.value;
        let code = '';
        
        codeInputs.forEach(input => {
            code += input.value.trim();
        });
        
        if (code.length !== 6) {
            showMessage('Please enter the full 6-digit code', 'error');
            return;
        }

        clearMessage();
        showMessage('Verifying code...', 'info');

        fetch('/verify_email_code/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({
                email: email,
                code: code
            })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw err; });
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                showMessage(data.message, 'success');
                if (data.redirect_url) {
                    setTimeout(() => {
                        window.location.href = data.redirect_url;
                    }, 1500);
                }
            } else {
                throw data;
            }
        })
        .catch(error => {
            console.error('Verification error:', error);
            showMessage(error.error || 'Verification failed. Please try again.', 'error');
        });
    }

    function startCountdownTimer(countdown) {
        const timer = setInterval(() => {
            countdown--;
            sendCodeBtn.textContent = `Send Code (${countdown}s)`;
            if (countdown <= 0) {
                clearInterval(timer);
                sendCodeBtn.disabled = false;
                sendCodeBtn.textContent = 'Send Code';
            }
        }, 1000);
    }

    function showMessage(message, type) {
        messageDiv.textContent = message;
        messageDiv.className = 'mt-4 text-center';
        messageDiv.classList.add(
            type === 'success' ? 'text-green-500' :
            type === 'error' ? 'text-red-500' :
            'text-blue-500'
        );
    }

    function clearMessage() {
        messageDiv.textContent = '';
        messageDiv.className = 'mt-4 text-center';
    }

    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
});