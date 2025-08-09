console.log("email_auth.js is running!");

// Utility function to get CSRF token from cookies
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

document.addEventListener("DOMContentLoaded", () => {
  const sendCodeBtn = document.getElementById('send-code-btn');
  if (!sendCodeBtn) return;

  sendCodeBtn.addEventListener('click', function(event) {
    event.preventDefault();
    sendCodeBtn.disabled = true;
    let countdown = 60;

    // Fetch POST request to send email code
    fetch('/members/send-email-code/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken')
      },
      body: JSON.stringify({}) // Use default email on server side
    })
    .then(response => response.json())
    .then(data => {
      if (data.ok) {
        // Create verification box if not present
        let verifyBox = document.getElementById('verify-box');
        if (!verifyBox) {
          verifyBox = document.createElement('div');
          verifyBox.id = 'verify-box';
          verifyBox.style.marginTop = '1rem';
          sendCodeBtn.parentNode.appendChild(verifyBox);
        }

        // Populate verification box
        verifyBox.innerHTML = `
          <p>${data.message} (Expires at: ${data.expires_at})</p>
          <input id="verify-code" type="text" maxlength="6" placeholder="Enter code" style="width: 100px; text-align: center; margin-right: 0.5rem;" />
          <button id="verify-btn" style="padding: 0.5rem 1rem;">Verify</button>
        `;
      } else {
        alert(data.error || 'An error occurred.');
      }
    })
    .catch(() => {
      alert('Failed to send code. Please try again.');
    })
    .finally(() => {
      // Start countdown timer
      const timer = setInterval(() => {
        countdown--;
        sendCodeBtn.textContent = `Send Code (${countdown}s)`;
        if (countdown <= 0) {
          clearInterval(timer);
          sendCodeBtn.disabled = false;
          sendCodeBtn.textContent = 'Send Code';
        }
      }, 1000);
    });
  });
});
