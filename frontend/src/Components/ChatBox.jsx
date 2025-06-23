import React, { useState } from 'react';

export default function ChatBox({ apiEndpoint, userId, sessionToken }) {
  const [query, setQuery] = useState('');
  const [chatLog, setChatLog] = useState([]);

  const sendChat = async () => {
    const response = await fetch(apiEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: userId,
        query,
        session_token: sessionToken,
        compliance_level: 'GDPR'
      }),
    });
    const data = await response.json();
    setChatLog([...chatLog, { query, response: data.response }]);
    setQuery('');
  };

  return (
    <div>
      <div>
        {chatLog.map((entry, idx) => (
          <div key={idx}>
            <b>You:</b> {entry.query}<br />
            <b>AI:</b> {entry.response}
          </div>
        ))}
      </div>
      <input
        value={query}
        onChange={e => setQuery(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') sendChat(); }}
      />
      <button onClick={sendChat}>Send</button>
    </div>
  );
}
