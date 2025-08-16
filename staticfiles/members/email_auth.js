// CSRF Token handling functions
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

function getCsrfToken() {
    // First try to get from meta tag
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    if (metaTag && metaTag.getAttribute('content')) {
        const token = metaTag.getAttribute('content');
        if (token && token.length > 10) { // Basic length validation
            return token;
        }
    }
    
    // Try to get from DOM input
    const csrfInput = document.querySelector("input[name='csrfmiddlewaretoken']");
    if (csrfInput && csrfInput.value) {
        const token = csrfInput.value;
        if (token && token.length > 10) { // Basic length validation
            return token;
        }
    }
    
    // Fallback to cookie
    const cookieToken = getCookie('csrftoken');
    if (cookieToken && cookieToken.length > 10) { // Basic length validation
        return cookieToken;
    }
    
    console.error('CSRF token not found or invalid length');
    return null;
}

document.addEventListener("DOMContentLoaded", () => {
    const sendCodeBtn = document.getElementById('send-code-btn');
    const messageDiv = document.getElementById('message');
    const codeInputs = document.querySelectorAll('input[type="text"][maxlength="1"]');
    
    // Progressive cooldown times (in seconds)
    const COOLDOWN_TIMES = [90, 180, 300, 900, 7200]; // 90s, 3min, 5min, 15min, 2hrs
    const MAX_INPUT_ATTEMPTS = 3;
    
    if (!sendCodeBtn) return;

    // Initialize button state and check for ongoing countdown
    const userEmail = document.getElementById('user-email')?.value;
    if (userEmail) {
        checkAndRestoreCountdown(userEmail);
    } else {
        sendCodeBtn.disabled = false;
        sendCodeBtn.classList.remove('opacity-50', 'cursor-not-allowed');
    }

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

    // Function to check and restore countdown from localStorage
    function checkAndRestoreCountdown(email) {
        const countdownKey = `email_countdown_${email}`;
        const countdownData = localStorage.getItem(countdownKey);
        
        if (countdownData) {
            const { endTime, attemptCount } = JSON.parse(countdownData);
            const now = Date.now();
            const remainingTime = Math.max(0, Math.ceil((endTime - now) / 1000));
            
            if (remainingTime > 0) {
                // Resume countdown
                startCountdownTimer(remainingTime, email, attemptCount);
                return;
            } else {
                // Countdown expired, clean up
                localStorage.removeItem(countdownKey);
            }
        }
        
        // No active countdown, enable button with correct text
        sendCodeBtn.disabled = false;
        sendCodeBtn.textContent = 'Send Code';
        sendCodeBtn.classList.remove('opacity-75', 'opacity-50', 'cursor-not-allowed');
        
        // Check and set input state based on failed attempts
        checkInputAttempts(email);
    }

    // Function to store countdown in localStorage with attempt count
    function storeCountdown(email, seconds, attemptCount = 1) {
        const countdownKey = `email_countdown_${email}`;
        const endTime = Date.now() + (seconds * 1000);
        localStorage.setItem(countdownKey, JSON.stringify({ endTime, attemptCount }));
    }

    // Function to clear countdown from localStorage
    function clearCountdown(email) {
        const countdownKey = `email_countdown_${email}`;
        localStorage.removeItem(countdownKey);
    }

    // Function to get attempt count from localStorage
    function getAttemptCount(email) {
        const countdownKey = `email_countdown_${email}`;
        const countdownData = localStorage.getItem(countdownKey);
        if (countdownData) {
            const { attemptCount } = JSON.parse(countdownData);
            return attemptCount || 1;
        }
        
        const attemptKey = `email_attempts_${email}`;
        const attempts = localStorage.getItem(attemptKey);
        return attempts ? parseInt(attempts) : 1;
    }

    // Function to increment attempt count
    function incrementAttemptCount(email) {
        const currentCount = getAttemptCount(email);
        const newCount = currentCount + 1;
        const attemptKey = `email_attempts_${email}`;
        localStorage.setItem(attemptKey, newCount.toString());
        return newCount;
    }

    // Function to get cooldown time based on attempt count
    function getCooldownTime(attemptCount) {
        if (attemptCount <= COOLDOWN_TIMES.length) {
            return COOLDOWN_TIMES[attemptCount - 1];
        }
        // For attempts beyond defined times, use 2 hours
        return COOLDOWN_TIMES[COOLDOWN_TIMES.length - 1];
    }

    // Input attempt tracking functions
    function storeInputAttempts(email, attempts) {
        const inputKey = `input_attempts_${email}`;
        localStorage.setItem(inputKey, attempts.toString());
    }

    function getInputAttempts(email) {
        const inputKey = `input_attempts_${email}`;
        const stored = localStorage.getItem(inputKey);
        return stored ? parseInt(stored) : 0;
    }

    function clearInputAttempts(email) {
        const inputKey = `input_attempts_${email}`;
        localStorage.removeItem(inputKey);
    }

    function incrementInputAttempts(email) {
        const current = getInputAttempts(email);
        const newCount = current + 1;
        storeInputAttempts(email, newCount);
        return newCount;
    }

    function checkInputAttempts(email) {
        const attempts = getInputAttempts(email);
        
        if (attempts >= MAX_INPUT_ATTEMPTS) {
            // Disable input until next send code
            codeInputs.forEach(input => {
                input.disabled = true;
                input.style.backgroundColor = '#f8f9fa';
                input.placeholder = '';
            });
            showMessage('Too many failed attempts. Send a new code to retry.', 'error');
        } else {
            // Enable input
            codeInputs.forEach(input => {
                input.disabled = false;
                input.style.backgroundColor = '';
                input.placeholder = '';
            });
        }
    }

    function sendVerificationCode(event) {
        if (event) event.preventDefault();
        
        // Immediate visual feedback
        sendCodeBtn.disabled = true;
        sendCodeBtn.textContent = 'Sending...';
        sendCodeBtn.classList.add('opacity-75');
        
        const email = document.getElementById('user-email')?.value;
        
        // Clear input attempts when sending new code
        if (email) {
            clearInputAttempts(email);
            // Re-enable inputs in case they were disabled
            codeInputs.forEach(input => {
                input.disabled = false;
                input.style.backgroundColor = '';
                input.placeholder = '';
            });
        }
        
        // Get current attempt count and calculate cooldown
        const attemptCount = email ? getAttemptCount(email) : 1;
        const cooldownTime = getCooldownTime(attemptCount);
        
        clearMessage();
        
        // Start progress
        if (window.updateEmailProgressBar) {
            window.updateEmailProgressBar(10);
        }
        
        if (!email) {
            showMessage('No email provided', 'error');
            // Reset button immediately on error
            sendCodeBtn.disabled = false;
            sendCodeBtn.textContent = 'Send Verification Code';
            sendCodeBtn.classList.remove('opacity-75', 'opacity-50', 'cursor-not-allowed');
            if (window.updateEmailProgressBar) {
                window.updateEmailProgressBar(0);
            }
            return;
        }

        // Check if config is loaded
        if (!window.emailAuthConfig || !window.emailAuthConfig.sendCodeUrl) {
            showMessage('Configuration error. Please refresh the page.', 'error');
            // Reset button immediately on error
            sendCodeBtn.disabled = false;
            sendCodeBtn.textContent = 'Send Verification Code';
            sendCodeBtn.classList.remove('opacity-75', 'opacity-50', 'cursor-not-allowed');
            if (window.updateEmailProgressBar) {
                window.updateEmailProgressBar(0);
            }
            return;
        }

        // Progress: sending request
        if (window.updateEmailProgressBar) {
            window.updateEmailProgressBar(25);
        }

        // Get CSRF token - ensure it's valid
        const csrfToken = getCsrfToken();
        if (!csrfToken) {
            showMessage('Security token not found. Please refresh the page and try again.', 'error');
            if (window.updateEmailProgressBar) {
                window.updateEmailProgressBar(0);
            }
            sendCodeBtn.disabled = false;
            sendCodeBtn.classList.remove('opacity-75', 'opacity-50', 'cursor-not-allowed');
            return;
        }

        // Prepare request body - ensure it's valid JSON
        let requestBody;
        try {
            requestBody = JSON.stringify({email: email});
        } catch (error) {
            console.error('Error preparing request:', error);
            showMessage('Failed to prepare request. Please try again.', 'error');
            if (window.updateEmailProgressBar) {
                window.updateEmailProgressBar(0);
            }
            sendCodeBtn.disabled = false;
            sendCodeBtn.classList.remove('opacity-75', 'opacity-50', 'cursor-not-allowed');
            return;
        }

        fetch(window.emailAuthConfig.sendCodeUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: requestBody
        })
        .then(response => {
            // Progress: response received
            if (window.updateEmailProgressBar) {
                window.updateEmailProgressBar(40);
            }
            if (!response.ok) {
                return response.json().then(err => { throw err; });
            }
            return response.json();
        })
        .then(data => {
            if (data.ok) {
                // Progress: code sent successfully
                if (window.updateEmailProgressBar) {
                    window.updateEmailProgressBar(50);
                }
                showMessage(data.message, 'success');
                
                // Increment attempt count for next time
                incrementAttemptCount(email);
                
                // Start countdown with progressive time - button text will be updated
                startCountdownTimer(cooldownTime, email, attemptCount);
            } else {
                throw data;
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showMessage(error.error || 'Failed to send code. Please try again.', 'error');
            // Progress: reset on error
            if (window.updateEmailProgressBar) {
                window.updateEmailProgressBar(0);
            }
            // Reset button immediately on error
            sendCodeBtn.disabled = false;
            sendCodeBtn.textContent = 'Send Verification Code';
            sendCodeBtn.classList.remove('opacity-75', 'opacity-50', 'cursor-not-allowed');
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

        // Check if input attempts exceeded
        const currentInputAttempts = getInputAttempts(email);
        if (currentInputAttempts >= MAX_INPUT_ATTEMPTS) {
            showMessage('Too many failed attempts. Send a new code to retry.', 'error');
            return;
        }

        clearMessage();
        showMessage('Verifying code...', 'info');
        
        // Progress: starting verification
        if (window.updateEmailProgressBar) {
            window.updateEmailProgressBar(75);
        }

        // Check if config is loaded
        if (!window.emailAuthConfig || !window.emailAuthConfig.verifyCodeUrl) {
            showMessage('Configuration error. Please refresh the page.', 'error');
            if (window.updateEmailProgressBar) {
                window.updateEmailProgressBar(0);
            }
            return;
        }

        // Get CSRF token - ensure it's valid
        const csrfToken = getCsrfToken();
        if (!csrfToken) {
            showMessage('Security token not found. Please refresh the page and try again.', 'error');
            if (window.updateEmailProgressBar) {
                window.updateEmailProgressBar(0);
            }
            return;
        }

        console.log('Verification attempt - CSRF token length:', csrfToken.length);

        fetch(window.emailAuthConfig.verifyCodeUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
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
                // Progress: verification complete
                if (window.updateEmailProgressBar) {
                    window.updateEmailProgressBar(100);
                }
                showMessage(data.message, 'success');
                
                // Clear all attempts on successful verification
                clearInputAttempts(email);
                // Clear attempt count for send code
                const attemptKey = `email_attempts_${email}`;
                localStorage.removeItem(attemptKey);
                
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
            
            // Increment input attempts on failed verification
            const newInputAttempts = incrementInputAttempts(email);
            
            if (newInputAttempts >= MAX_INPUT_ATTEMPTS) {
                // Disable inputs after max attempts
                codeInputs.forEach(input => {
                    input.disabled = true;
                    input.style.backgroundColor = '#f8f9fa';
                    input.value = '';
                });
                showMessage('Too many failed attempts. Send a new code to retry.', 'error');
            } else {
                // Clear input fields for next attempt
                codeInputs.forEach(input => input.value = '');
                codeInputs[0].focus();
                showMessage(error.error || `Verification failed. ${MAX_INPUT_ATTEMPTS - newInputAttempts} attempts remaining.`, 'error');
            }
            
            // Reset progress on verification error
            if (window.updateEmailProgressBar) {
                window.updateEmailProgressBar(50); // Back to "code sent" state
            }
        });
    }

    function startCountdownTimer(countdown, email = null, attemptCount = 1) {
        // Get email if not provided
        if (!email) {
            email = document.getElementById('user-email')?.value;
        }
        
        // Store countdown in localStorage with attempt count
        if (email) {
            storeCountdown(email, countdown, attemptCount);
        }
        
        // Ensure button is disabled during countdown and set initial text
        sendCodeBtn.disabled = true;
        sendCodeBtn.classList.remove('opacity-75'); // Remove the "Sending..." styling
        sendCodeBtn.classList.add('opacity-50', 'cursor-not-allowed');
        
        // Format countdown time for display
        function formatTime(seconds) {
            if (seconds >= 3600) {
                const hours = Math.floor(seconds / 3600);
                const minutes = Math.floor((seconds % 3600) / 60);
                const secs = seconds % 60;
                return `${hours}h ${minutes}m ${secs}s`;
            } else if (seconds >= 60) {
                const minutes = Math.floor(seconds / 60);
                const secs = seconds % 60;
                return `${minutes}m ${secs}s`;
            } else {
                return `${seconds}s`;
            }
        }
        
        sendCodeBtn.textContent = `Send Code (${formatTime(countdown)})`; // Set initial countdown text
        
        const timer = setInterval(() => {
            countdown--;
            sendCodeBtn.textContent = `Send Code (${formatTime(countdown)})`;
            
            if (countdown <= 0) {
                clearInterval(timer);
                sendCodeBtn.disabled = false;
                sendCodeBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                sendCodeBtn.textContent = 'Send Code';
                
                // Clear countdown from localStorage
                if (email) {
                    clearCountdown(email);
                }
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