// frontend2/src/App.jsx
import { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [message, setMessage] = useState('Loading...');
  const [error, setError] = useState(null);
  const [status, setStatus] = useState('');

  useEffect(() => {
    fetch('/api/test/')
      .then(response => {
        setStatus(`Status: ${response.status} ${response.statusText}`);
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          return response.json();
        }
        return response.text();
      })
      .then(data => {
        if (typeof data === 'object' && data.message) {
          setMessage(data.message);
          console.log('✅ Success:', data);
        } else {
          setMessage(`Received: ${data}`);
        }
        setError(null);
      })
      .catch(err => {
        console.error('❌ Fetch error:', err);
        setError(err.message);
        setMessage('Failed to connect to Django');
      });
  }, []);

  return (
    <div className="App">
      <h1>Django + Vite React</h1>
      <div>
        <h2>Backend Connection Test</h2>
        <p><strong>Message:</strong> {message}</p>
        <p><strong>{status}</strong></p>
        {error && <p style={{ color: 'red' }}><strong>Error:</strong> {error}</p>}
      </div>
    </div>
  );
}

export default App;