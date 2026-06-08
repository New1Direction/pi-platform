import { useState, useRef, useEffect } from 'react';
import { Send, Terminal } from 'lucide-react';
import { translateChat } from '../lib/api';

type Msg = { role: 'user' | 'assistant' | 'error'; text: string; ts: string };

export function ChatView({ sessionId }: { sessionId: string | null }) {
  const [messages, setMessages] = useState<Msg[]>([
    { role: 'assistant', text: 'PI Security Copilot online. Describe a composition in plain language and I\'ll translate it into an ExplicitCompositionRequest. Example: "scan this solidity file for reentrancy vulnerabilities"', ts: new Date().toLocaleTimeString() },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const send = async () => {
    if (!input.trim() || loading || !sessionId) return;
    const text = input.trim();
    setInput('');
    const ts = new Date().toLocaleTimeString();
    setMessages(m => [...m, { role: 'user', text, ts }]);
    setLoading(true);
    try {
      const r = await translateChat(sessionId, text);
      const reply = r.explanation + (r.proposed_composition
        ? `\n\n\`\`\`json\n${JSON.stringify(r.proposed_composition, null, 2)}\n\`\`\``
        : '');
      setMessages(m => [...m, { role: 'assistant', text: reply, ts: new Date().toLocaleTimeString() }]);
    } catch (e) {
      setMessages(m => [...m, { role: 'error', text: String(e), ts: new Date().toLocaleTimeString() }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>

      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '8px 16px', borderBottom: 'var(--bw)',
        background: 'var(--ink)', color: 'var(--white)', flexShrink: 0,
      }}>
        <Terminal size={14} style={{ color: 'var(--yellow)' }} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
          PI SECURITY COPILOT
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#666', marginLeft: 'auto' }}>
          {sessionId ? `session: ${sessionId.slice(0, 14)}…` : 'no session'}
        </span>
      </div>

      {/* Messages */}
      <div style={{ flex: 1, overflow: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
        {messages.map((m, i) => (
          <div key={i} style={{
            alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
            maxWidth: '75%',
          }}>
            <div style={{
              fontSize: 9, fontFamily: 'var(--font-mono)', color: '#aaa',
              marginBottom: 3, textAlign: m.role === 'user' ? 'right' : 'left',
              textTransform: 'uppercase', letterSpacing: '0.06em',
            }}>
              {m.role === 'user' ? 'OPERATOR' : m.role === 'error' ? 'ERROR' : 'COPILOT'} · {m.ts}
            </div>
            <div style={{
              padding: '10px 14px',
              background: m.role === 'user' ? 'var(--ink)' : m.role === 'error' ? '#ffd8d0' : 'var(--white)',
              color: m.role === 'user' ? 'var(--white)' : m.role === 'error' ? 'var(--red)' : 'var(--ink)',
              border: m.role === 'error' ? '2px solid var(--red)' : 'var(--bw)',
              boxShadow: 'var(--shadow-sm)',
              fontFamily: m.text.includes('```') ? 'var(--font-mono)' : 'var(--font-sans)',
              fontSize: 12, lineHeight: 1.55,
              whiteSpace: 'pre-wrap', wordBreak: 'break-word',
            }}>
              {m.text}
            </div>
          </div>
        ))}
        {loading && (
          <div style={{ alignSelf: 'flex-start', fontFamily: 'var(--font-mono)', fontSize: 12, color: '#aaa', letterSpacing: '0.1em' }}>
            thinking_
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div style={{
        display: 'flex', gap: 0,
        borderTop: 'var(--bw)', flexShrink: 0,
      }}>
        <input
          className="input"
          style={{ flex: 1, border: 'none', padding: '12px 16px', fontSize: 13 }}
          placeholder={sessionId ? 'describe a composition…' : 'waiting for session…'}
          value={input}
          disabled={!sessionId || loading}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }}
        />
        <button
          className="btn btn-ink"
          onClick={send}
          disabled={!input.trim() || loading || !sessionId}
          style={{
            borderLeft: 'var(--bw)', borderTop: 'none', borderBottom: 'none', borderRight: 'none',
            padding: '0 20px', boxShadow: 'none',
            opacity: (!input.trim() || loading || !sessionId) ? 0.4 : 1,
          }}
        >
          <Send size={14} />
        </button>
      </div>
    </div>
  );
}
