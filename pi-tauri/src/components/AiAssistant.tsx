import { useState, useRef, useEffect, useCallback } from 'react';
import { Bot, Send, Settings, X, ChevronRight, Loader } from 'lucide-react';
import { Tooltip } from './Tooltip';

type Role = 'user' | 'assistant' | 'error';
type Msg = { role: Role; text: string };

const SYSTEM_PROMPT = `You are PI Assistant, an expert guide to the PI Platform — an enterprise security agent orchestration system with 248 specialized micro-agents.

Key concepts:
- **StateLedger**: Hash-chain audit log of every agent execution. Tamper-evident, tenant-scoped.
- **AgentRouter**: Keyword-dispatch routing. Maps user intent to one of 248 specialized agents.
- **Compositions**: DAGs of agent nodes. You configure, simulate (safe dry-run), then submit them.
- **Trust Tiers**: GOVERNED > AUDITED > VERIFIED > UNVERIFIED. Indicates review/audit depth.
- **Runtimes**: pi-extension-governor, pi-semantic-validator, pi-semantic-diff, pi-blast-radius, pi-interoperability-layer, pi-semantic-recon, pi-catalog-integration.
- **Operations**: SANDBOX (isolated execution), SCAN (issue detection), VALIDATE (correctness check), DIFF (version compare), ANALYZE (deep inspection).

Help users:
1. Understand what PI Platform is and how it works
2. Build compositions — give concrete JSON examples using correct runtime/operation values
3. Interpret ledger entries, risk scores (0-100), anomaly flags
4. Debug composition errors (DAG cycles, bounds violations, policy blocks)
5. Find the right agent for a security task

Keep responses concise and practical. Use code blocks for JSON. When showing a composition node example, use pi-extension-governor as the runtime and SANDBOX or SCAN as the operation.`;

const QUICK = [
  'What is PI Platform and how do I start?',
  'How do I build a composition?',
  'What do risk scores mean?',
  'Show me a composition JSON example',
  'How do trust tiers work?',
  'What are anomaly alerts in the ledger?',
];

const LS_KEY_APIKEY = 'pi_ai_apikey';
const LS_KEY_MODEL  = 'pi_ai_model';

const MODELS = [
  { id: 'claude-haiku-4-5-20251001', label: 'Haiku 4.5 (fast)' },
  { id: 'claude-sonnet-4-6',         label: 'Sonnet 4.6 (best)' },
];

type Props = { onClose: () => void };

export function AiAssistant({ onClose }: Props) {
  const [messages, setMessages] = useState<Msg[]>([
    { role: 'assistant', text: 'Hi! I\'m the PI Assistant. I can help you understand the platform, build compositions, and interpret results.\n\nWhat would you like to know?' },
  ]);
  const [input, setInput]         = useState('');
  const [streaming, setStreaming] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [apiKey, setApiKey]       = useState(() => localStorage.getItem(LS_KEY_APIKEY) ?? '');
  const [model, setModel]         = useState(() => localStorage.getItem(LS_KEY_MODEL) ?? MODELS[0].id);
  const [draftKey, setDraftKey]   = useState(apiKey);
  const [draftModel, setDraftModel] = useState(model);
  const bottomRef   = useRef<HTMLDivElement>(null);
  const abortRef    = useRef<AbortController | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const saveSettings = () => {
    localStorage.setItem(LS_KEY_APIKEY, draftKey);
    localStorage.setItem(LS_KEY_MODEL, draftModel);
    setApiKey(draftKey);
    setModel(draftModel);
    setShowSettings(false);
  };

  const send = useCallback(async (text: string) => {
    if (!text.trim() || streaming) return;
    const userMsg = text.trim();
    setInput('');
    setMessages(m => [...m, { role: 'user', text: userMsg }]);

    if (!apiKey) {
      setMessages(m => [...m, { role: 'error', text: 'No API key set. Click the settings icon to add your Anthropic API key.' }]);
      return;
    }

    setStreaming(true);
    abortRef.current = new AbortController();

    const history = messages
      .filter(m => m.role !== 'error')
      .map(m => ({ role: m.role as 'user' | 'assistant', content: m.text }));

    setMessages(m => [...m, { role: 'assistant', text: '' }]);

    try {
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        signal: abortRef.current.signal,
        headers: {
          'Content-Type':    'application/json',
          'x-api-key':       apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model,
          max_tokens: 1024,
          stream: true,
          system: SYSTEM_PROMPT,
          messages: [...history, { role: 'user', content: userMsg }],
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: { message: res.statusText } }));
        throw new Error(err?.error?.message ?? `HTTP ${res.status}`);
      }

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6).trim();
          if (data === '[DONE]') continue;
          try {
            const ev = JSON.parse(data);
            if (ev.type === 'content_block_delta' && ev.delta?.type === 'text_delta') {
              const chunk = ev.delta.text as string;
              setMessages(m => {
                const copy = [...m];
                copy[copy.length - 1] = { role: 'assistant', text: copy[copy.length - 1].text + chunk };
                return copy;
              });
            }
          } catch { /* partial JSON – skip */ }
        }
      }
    } catch (e: unknown) {
      if (e instanceof Error && e.name === 'AbortError') return;
      const msg = e instanceof Error ? e.message : String(e);
      setMessages(m => {
        const copy = [...m];
        copy[copy.length - 1] = { role: 'error', text: `Error: ${msg}` };
        return copy;
      });
    } finally {
      setStreaming(false);
    }
  }, [apiKey, model, messages, streaming]);

  const stop = () => { abortRef.current?.abort(); setStreaming(false); };

  return (
    <div className="win" style={{ width: 350, flexShrink: 0, position: 'relative' }}>

      {/* ── Header ── */}
      <div className="win-title ai" style={{ flexShrink: 0 }}>
        <Bot size={11} style={{ flexShrink: 0 }} />
        <span style={{ flex: 1, fontSize: 11 }}>PI ASSISTANT</span>
        <div style={{ display: 'flex', gap: 2 }}>
          <Tooltip tip={'Set your Anthropic API key and model.\nKey is stored in localStorage only —\nnever sent anywhere except api.anthropic.com.'} pos="left">
            <button className="win-title-btn" onClick={() => { setShowSettings(s => !s); setDraftKey(apiKey); setDraftModel(model); }}>
              <Settings size={8} />
            </button>
          </Tooltip>
          <Tooltip tip="Close AI panel (Ctrl+I to reopen)" pos="left">
            <button className="win-title-btn" onClick={onClose}>✕</button>
          </Tooltip>
        </div>
      </div>

      {/* ── Settings overlay ── */}
      {showSettings && (
        <div style={{
          position: 'absolute', top: 38, left: 0, right: 0, zIndex: 10,
          background: 'var(--white)', border: 'var(--bw)', borderTop: 'none',
          padding: 16, display: 'flex', flexDirection: 'column', gap: 10,
        }}>
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 12, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase' }}>Anthropic API Key</div>
          <input
            type="password"
            className="input"
            placeholder="sk-ant-…"
            value={draftKey}
            onChange={e => setDraftKey(e.target.value)}
            style={{ fontSize: 12 }}
          />
          <div style={{ fontFamily: 'var(--font-sans)', fontSize: 12, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase' }}>Model</div>
          <select className="input" value={draftModel} onChange={e => setDraftModel(e.target.value)} style={{ fontSize: 12 }}>
            {MODELS.map(m => <option key={m.id} value={m.id}>{m.label}</option>)}
          </select>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-ink" style={{ flex: 1, justifyContent: 'center', fontSize: 11 }} onClick={saveSettings}>Save</button>
            <button className="btn btn-sm" onClick={() => setShowSettings(false)}>Cancel</button>
          </div>
          {!apiKey && (
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)', lineHeight: 1.5 }}>
              Get your key at console.anthropic.com. It stays in localStorage, never leaves your machine.
            </div>
          )}
        </div>
      )}

      {/* ── Messages ── */}
      <div className="win-content" style={{ flex: 1, overflow: 'auto', padding: 10, display: 'flex', flexDirection: 'column', gap: 8, background: 'var(--white)' }}>

        {/* Quick action chips — show when only welcome message visible */}
        {messages.length === 1 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 4 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#888', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 2 }}>Quick questions</div>
            {QUICK.map(q => (
              <button key={q} className="ai-chip" onClick={() => send(q)}>
                <ChevronRight size={11} style={{ flexShrink: 0, color: 'var(--c-ai)', marginRight: 4 }} />
                {q}
              </button>
            ))}
          </div>
        )}

        {messages.map((m, i) => (
          <div key={i} className={m.role === 'user' ? 'ai-msg-user' : m.role === 'error' ? 'ai-msg-error' : 'ai-msg-assistant'}>
            {m.role === 'assistant' && m.text === '' && streaming ? (
              <span style={{ color: '#aaa', fontFamily: 'var(--font-mono)', fontSize: 12 }}>▋</span>
            ) : m.text}
          </div>
        ))}

        {/* Show quick actions again after a conversation */}
        {messages.length > 2 && messages.length % 6 === 0 && (
          <div style={{ borderTop: 'var(--bw-light)', paddingTop: 10, display: 'flex', flexDirection: 'column', gap: 5 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#aaa', textTransform: 'uppercase', letterSpacing: '0.06em' }}>More questions</div>
            {QUICK.slice(0, 3).map(q => (
              <button key={q} className="ai-chip" onClick={() => send(q)} style={{ fontSize: 11 }}>{q}</button>
            ))}
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* ── Input ── */}
      <div style={{ borderTop: 'var(--bw)', flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 0 }}>
        <div style={{ display: 'flex', alignItems: 'flex-end' }}>
          <textarea
            ref={textareaRef}
            style={{
              flex: 1,
              border: 'none',
              borderRight: 'var(--bw)',
              padding: '10px 14px',
              fontFamily: 'var(--font-sans)',
              fontSize: 13,
              resize: 'none',
              minHeight: 44,
              maxHeight: 120,
              lineHeight: 1.45,
              background: 'var(--white)',
              color: 'var(--ink)',
              outline: 'none',
            }}
            placeholder={apiKey ? 'Ask anything about PI Platform…' : 'Set your API key to start ↗'}
            value={input}
            rows={1}
            disabled={!apiKey}
            onChange={e => {
              setInput(e.target.value);
              e.target.style.height = 'auto';
              e.target.style.height = `${Math.min(e.target.scrollHeight, 120)}px`;
            }}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input); }
            }}
          />
          <button
            onClick={streaming ? stop : () => send(input)}
            style={{
              width: 44, height: 44, border: 'none', flexShrink: 0, cursor: 'pointer',
              background: streaming ? 'var(--red)' : apiKey && input.trim() ? 'var(--c-ai)' : 'var(--muted)',
              color: 'var(--white)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              transition: 'background 100ms',
            }}
          >
            {streaming ? <X size={15} /> : <Send size={15} />}
          </button>
        </div>
        {streaming && (
          <div style={{
            padding: '4px 14px', fontFamily: 'var(--font-mono)', fontSize: 10,
            color: 'var(--c-ai)', display: 'flex', alignItems: 'center', gap: 5,
            borderTop: '1px solid var(--line)',
          }}>
            <Loader size={9} className="spin" /> generating · Shift+Enter for newline · Enter to send
          </div>
        )}
      </div>
    </div>
  );
}
