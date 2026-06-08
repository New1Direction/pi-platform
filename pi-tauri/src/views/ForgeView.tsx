import { useState } from 'react';
import { Hammer, Eye, ShieldCheck, Save, RefreshCw } from 'lucide-react';
import {
  forgeGenerate,
  forgeAudit,
  forgeSave,
  getForgeApiKey,
  setForgeApiKey,
} from '../lib/api';
import type { ForgeGenerateResponse, ForgeAuditResponse } from '../types';

type Stage = 'idle' | 'generating' | 'generated' | 'saving' | 'saved';

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#cc0022',
  HIGH:     '#cc6600',
  MEDIUM:   '#886600',
  LOW:      '#336600',
};

export function ForgeView() {
  // Form
  const [description, setDescription] = useState('');
  const [keywordsRaw, setKeywordsRaw]  = useState('');
  const [exampleInput, setExampleInput] = useState('');
  const [apiKey, setApiKeyState]        = useState(() => getForgeApiKey());

  // Stage + results
  const [stage, setStage]   = useState<Stage>('idle');
  const [error, setError]   = useState<string | null>(null);
  const [generated, setGenerated] = useState<ForgeGenerateResponse | null>(null);
  const [audit, setAudit]         = useState<ForgeAuditResponse | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [rightTab, setRightTab]   = useState<'code' | 'audit'>('code');

  const keywords = keywordsRaw
    .split(/[\n,]+/)
    .map(k => k.trim())
    .filter(Boolean);

  const canGenerate = description.trim().length > 0 && keywords.length > 0 && apiKey.trim().length > 0;
  const canSave     = stage === 'generated' && audit?.passed === true && generated != null;

  function handleApiKeyChange(k: string) {
    setApiKeyState(k);
    setForgeApiKey(k);
  }

  async function handleGenerate() {
    if (!canGenerate) return;
    setStage('generating');
    setError(null);
    setGenerated(null);
    setAudit(null);
    setSavedPath(null);

    try {
      const result = await forgeGenerate(
        { description: description.trim(), keywords, example_input: exampleInput.trim() },
        apiKey.trim(),
      );
      setGenerated(result);

      // Auto-audit after generation
      const auditResult = await forgeAudit(result.code, result.agent_class_name);
      setAudit(auditResult);
      setRightTab(auditResult.passed ? 'code' : 'audit');
      setStage('generated');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setStage('idle');
    }
  }

  async function handleSave() {
    if (!canSave || !generated) return;
    setStage('saving');
    setError(null);

    try {
      const result = await forgeSave(
        { code: generated.code, agent_name: generated.agent_class_name, description: description.trim() },
        apiKey.trim(),
      );
      setSavedPath(result.filename);
      setStage('saved');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setStage('generated');
    }
  }

  function handleReset() {
    setStage('idle');
    setGenerated(null);
    setAudit(null);
    setSavedPath(null);
    setError(null);
  }

  const isLoading = stage === 'generating' || stage === 'saving';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>

      {/* ── Toolbar ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '8px 16px', borderBottom: 'var(--bw)',
        background: 'var(--paper-2)', flexShrink: 0,
      }}>
        <Hammer size={13} style={{ color: '#7a2900', flexShrink: 0 }} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color: '#7a2900' }}>
          AGENT FORGE
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#888', marginLeft: 4 }}>
          AI-assisted micro-agent generator — BYOK · agents land in pending/ as UNVERIFIED
        </span>
        {(stage === 'generated' || stage === 'saved') && (
          <button className="btn btn-sm" onClick={handleReset} style={{ marginLeft: 'auto', flexShrink: 0 }}>
            <RefreshCw size={10} style={{ marginRight: 4 }} />
            New agent
          </button>
        )}
      </div>

      {/* ── Main two-panel layout ── */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

        {/* ── LEFT: form ── */}
        <div style={{
          width: 300, flexShrink: 0,
          borderRight: 'var(--bw)',
          display: 'flex', flexDirection: 'column',
          overflow: 'auto',
          background: 'var(--paper-2)',
        }}>
          <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 12 }}>

            {/* Description */}
            <div>
              <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#555', display: 'block', marginBottom: 4 }}>
                Description *
              </label>
              <textarea
                className="input"
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="Detects SQL injection patterns in user-submitted query strings"
                rows={3}
                disabled={isLoading}
                style={{ width: '100%', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 11, boxSizing: 'border-box' }}
              />
            </div>

            {/* Keywords */}
            <div>
              <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#555', display: 'block', marginBottom: 4 }}>
                Keywords * <span style={{ fontWeight: 400, color: '#888' }}>(one per line or comma-sep)</span>
              </label>
              <textarea
                className="input"
                value={keywordsRaw}
                onChange={e => setKeywordsRaw(e.target.value)}
                placeholder={"sql injection scan\nquery validation\ndatabase input check"}
                rows={4}
                disabled={isLoading}
                style={{ width: '100%', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 11, boxSizing: 'border-box' }}
              />
              {keywords.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 4 }}>
                  {keywords.map(k => (
                    <span key={k} style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9,
                      padding: '1px 5px', background: 'var(--white)',
                      border: '1px solid var(--paper-3)',
                      textTransform: 'uppercase', letterSpacing: '0.04em',
                    }}>{k}</span>
                  ))}
                </div>
              )}
            </div>

            {/* Example input */}
            <div>
              <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#555', display: 'block', marginBottom: 4 }}>
                Example input <span style={{ fontWeight: 400, color: '#888' }}>(optional)</span>
              </label>
              <textarea
                className="input"
                value={exampleInput}
                onChange={e => setExampleInput(e.target.value)}
                placeholder="SELECT * FROM users WHERE id = '1' OR '1'='1'"
                rows={2}
                disabled={isLoading}
                style={{ width: '100%', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 11, boxSizing: 'border-box' }}
              />
            </div>

            {/* API Key */}
            <div>
              <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#555', display: 'block', marginBottom: 4 }}>
                Anthropic API key * <span style={{ fontWeight: 400, color: '#888' }}>(BYOK · stored locally)</span>
              </label>
              <input
                type="password"
                className="input"
                value={apiKey}
                onChange={e => handleApiKeyChange(e.target.value)}
                placeholder="sk-ant-…"
                disabled={isLoading}
                style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: 11, boxSizing: 'border-box' }}
              />
            </div>

            {/* Generate button */}
            <button
              className="btn"
              onClick={handleGenerate}
              disabled={!canGenerate || isLoading}
              style={{
                background: canGenerate && !isLoading ? 'linear-gradient(to right, #7a2900, #aa3a00)' : undefined,
                color: canGenerate && !isLoading ? '#fff' : undefined,
                fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              }}
            >
              {stage === 'generating' ? (
                <>⚙ Generating…</>
              ) : (
                <><Hammer size={11} /> Generate agent</>
              )}
            </button>

            {error && (
              <div style={{
                padding: '8px 10px', background: '#fff0f0',
                border: '1px solid #ffaaaa',
                fontFamily: 'var(--font-mono)', fontSize: 10, color: '#cc0022',
                wordBreak: 'break-all',
              }}>
                {error}
              </div>
            )}

            {/* Trust tier explainer */}
            <div style={{
              padding: '8px 10px',
              border: '1px solid var(--paper-3)',
              background: 'var(--white)',
              fontFamily: 'var(--font-mono)', fontSize: 10, color: '#666',
              lineHeight: 1.5,
            }}>
              <div style={{ fontWeight: 700, marginBottom: 3, color: '#333' }}>Trust lifecycle</div>
              <div><span style={{ color: '#cc8800' }}>UNVERIFIED</span> → AI-generated, pending/</div>
              <div><span style={{ color: '#226600' }}>VERIFIED</span> → human review passed</div>
              <div><span style={{ color: '#005599' }}>AUDITED</span> → tests pass</div>
              <div><span style={{ color: '#333' }}>GOVERNED</span> → security sign-off</div>
            </div>
          </div>
        </div>

        {/* ── RIGHT: output ── */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

          {/* right toolbar with tabs */}
          {stage === 'generated' || stage === 'saved' || stage === 'saving' ? (
            <>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 0,
                padding: '0 12px', borderBottom: 'var(--bw)',
                background: 'var(--paper-2)', flexShrink: 0, minHeight: 34,
              }}>
                {(['code', 'audit'] as const).map((t, i) => (
                  <button
                    key={t}
                    onClick={() => setRightTab(t)}
                    style={{
                      padding: '6px 14px',
                      background: rightTab === t ? 'var(--white)' : 'transparent',
                      border: 'none',
                      borderRight: i === 0 ? '1px solid var(--paper-3)' : 'none',
                      fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                      letterSpacing: '0.05em', textTransform: 'uppercase',
                      color: rightTab === t ? 'var(--ink)' : '#888',
                      cursor: 'pointer',
                      display: 'flex', alignItems: 'center', gap: 5,
                    }}
                  >
                    {t === 'code' ? <Eye size={10} /> : <ShieldCheck size={10} />}
                    {t}
                    {t === 'audit' && audit && (
                      <span style={{
                        marginLeft: 3, padding: '0 4px',
                        background: audit.passed ? '#d4edda' : '#f8d7da',
                        color: audit.passed ? '#155724' : '#721c24',
                        fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
                        border: `1px solid ${audit.passed ? '#c3e6cb' : '#f5c6cb'}`,
                      }}>
                        {audit.passed ? 'PASS' : 'FAIL'}
                      </span>
                    )}
                  </button>
                ))}

                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
                  {generated && (
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#888' }}>
                      {generated.agent_class_name} · {generated.model_used}
                    </span>
                  )}
                  {stage === 'saved' ? (
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                      color: '#155724', padding: '3px 8px',
                      background: '#d4edda', border: '1px solid #c3e6cb',
                    }}>
                      ✓ saved · {savedPath}
                    </span>
                  ) : (
                    <button
                      className="btn btn-sm"
                      onClick={handleSave}
                      disabled={!canSave || stage === 'saving'}
                      style={{
                        background: canSave ? 'linear-gradient(to right, #7a2900, #aa3a00)' : undefined,
                        color: canSave ? '#fff' : undefined,
                        display: 'flex', alignItems: 'center', gap: 5,
                      }}
                    >
                      {stage === 'saving' ? (
                        <>⚙ Saving…</>
                      ) : (
                        <><Save size={10} /> Save to pending/</>
                      )}
                    </button>
                  )}
                </div>
              </div>

              <div style={{ flex: 1, overflow: 'auto' }}>

                {/* Code tab */}
                {rightTab === 'code' && generated && (
                  <div style={{ minHeight: '100%', background: 'var(--white)' }}>
                    <pre style={{
                      margin: 0, padding: 16,
                      fontFamily: 'var(--font-mono)', fontSize: 11,
                      lineHeight: 1.55, color: 'var(--ink)',
                      tabSize: 4,
                      whiteSpace: 'pre',
                      overflowX: 'auto',
                    }}>
                      {generated.code}
                    </pre>

                    {/* Wiring recipe — what a human reviewer does after audit passes */}
                    <div style={{ borderTop: '1px solid var(--paper-3)', background: 'var(--paper-2)' }}>
                      <div style={{
                        padding: '8px 16px 4px',
                        fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                        textTransform: 'uppercase', letterSpacing: '0.06em', color: '#7a2900',
                      }}>
                        Wiring — after audit + human review (UNVERIFIED → VERIFIED)
                      </div>
                      <pre style={{
                        margin: 0, padding: '4px 16px 16px',
                        fontFamily: 'var(--font-mono)', fontSize: 10.5,
                        lineHeight: 1.5, color: '#555',
                        whiteSpace: 'pre',
                        overflowX: 'auto',
                      }}>
                        {generated.router_snippet}
                      </pre>
                    </div>
                  </div>
                )}

                {/* Audit tab */}
                {rightTab === 'audit' && audit && (
                  <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>

                    {/* Overall verdict */}
                    <div style={{
                      padding: '10px 14px',
                      background: audit.passed ? '#d4edda' : '#f8d7da',
                      border: `1px solid ${audit.passed ? '#c3e6cb' : '#f5c6cb'}`,
                      fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700,
                      color: audit.passed ? '#155724' : '#721c24',
                    }}>
                      {audit.passed ? '✓ Audit passed — safe to save' : '✗ Audit failed — fix issues before saving'}
                    </div>

                    {/* Structural checks */}
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#555', marginBottom: 6 }}>
                        Structural checks
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                        {Object.entries(audit.structural_checks).map(([key, ok]) => (
                          <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-mono)', fontSize: 10 }}>
                            <span style={{ color: ok ? '#155724' : '#721c24', fontWeight: 700 }}>
                              {ok ? '✓' : '✗'}
                            </span>
                            <span style={{ color: ok ? '#155724' : '#721c24' }}>{key}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Findings */}
                    {audit.findings.length > 0 && (
                      <div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#555', marginBottom: 6 }}>
                          Findings ({audit.findings.length})
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                          {audit.findings.map((f, i) => (
                            <div key={i} style={{
                              display: 'flex', alignItems: 'flex-start', gap: 8,
                              padding: '6px 10px',
                              background: 'var(--paper-2)',
                              border: `1px solid ${SEVERITY_COLOR[f.severity] ?? '#ccc'}22`,
                              borderLeft: `3px solid ${SEVERITY_COLOR[f.severity] ?? '#ccc'}`,
                            }}>
                              <span style={{
                                fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
                                color: SEVERITY_COLOR[f.severity] ?? '#888',
                                flexShrink: 0, paddingTop: 1,
                              }}>
                                {f.severity}
                              </span>
                              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--ink)', lineHeight: 1.4 }}>
                                {f.message}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {audit.findings.length === 0 && (
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#155724', padding: '8px 12px', background: '#d4edda', border: '1px solid #c3e6cb' }}>
                        No findings — code is clean
                      </div>
                    )}
                  </div>
                )}
              </div>
            </>
          ) : (
            /* Empty state */
            <div style={{
              flex: 1, display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center',
              color: '#aaa', gap: 10,
            }}>
              {stage === 'generating' ? (
                <>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: '#7a2900' }}>
                    ⚙ Generating micro-agent…
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#888' }}>
                    Claude is writing your agent code and audit will follow automatically
                  </div>
                </>
              ) : (
                <>
                  <Hammer size={36} style={{ color: '#d4a070', opacity: 0.5 }} />
                  <div style={{ fontFamily: 'var(--font-ui)', fontSize: 14, fontWeight: 700, color: '#7a2900' }}>
                    Agent Forge
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#888', textAlign: 'center', maxWidth: 320, lineHeight: 1.5 }}>
                    Fill in the form on the left and click Generate.<br />
                    Claude will produce a new micro-agent following the PI Platform architecture.<br />
                    The code will be audited automatically before you can save it.
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
