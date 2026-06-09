import { useState, useEffect } from 'react';
import { Eye, Save, ChevronDown, ChevronRight, X, FlaskConical } from 'lucide-react';
import {
  forgeGenerate,
  forgeAudit,
  forgeSave,
  forgeListPending,
  forgePromote,
  forgeTest,
  getForgeApiKey,
  setForgeApiKey,
} from '../lib/api';
import { agentTypeOf } from '../lib/agentdex';
import { Creature } from '../components/Creature';
import type {
  ForgeGenerateResponse, ForgeAuditResponse, ForgePendingAgent, ForgePromoteResponse,
  ForgeTestSample, ForgeTestResponse,
} from '../types';

type Stage = 'idle' | 'generating' | 'generated' | 'saving' | 'saved';
type Mode = 'generate' | 'pending';

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#ff5a6a', HIGH: '#ff9a3a', MEDIUM: '#ffd24a', LOW: '#9ad36a',
};

// ── Trust tier = the level-up track (cosmetic; mirrors backend trust_tier) ──
const TIERS = ['UNVERIFIED', 'VERIFIED', 'AUDITED', 'GOVERNED'] as const;
type Tier = typeof TIERS[number];
const TIER_META: Record<Tier, { color: string; icon: string; blurb: string }> = {
  UNVERIFIED: { color: '#ffb400', icon: '◆', blurb: 'freshly forged' },
  VERIFIED:   { color: '#5fd38a', icon: '✦', blurb: 'wired in by a human' },
  AUDITED:    { color: '#5fb0ff', icon: '★', blurb: 'survived its tests' },
  GOVERNED:   { color: '#c79bff', icon: '♛', blurb: 'security sign-off' },
};

// ─── small pieces ────────────────────────────────────────────────────────────

function Sparks({ n = 6 }: { n?: number }) {
  return (
    <div style={{ position: 'relative', width: 0, height: 0 }}>
      {Array.from({ length: n }).map((_, i) => (
        <span key={i} className="forge-spark" style={{
          left: (i - n / 2) * 5, bottom: 0,
          ['--sx' as string]: `${(i - n / 2) * 4}px`,
          animationDelay: `${(i * 0.13) % 0.9}s`,
        }} />
      ))}
    </div>
  );
}

function TierTrack({ current }: { current: Tier }) {
  const curIdx = TIERS.indexOf(current);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
      {TIERS.map((t, i) => {
        const m = TIER_META[t];
        const earned = i <= curIdx;
        const isCur = i === curIdx;
        return (
          <div key={t} style={{ display: 'flex', alignItems: 'center', flex: i < TIERS.length - 1 ? 1 : '0 0 auto' }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
              <div
                className={isCur ? 'forge-tier-pulse' : undefined}
                style={{
                  width: 24, height: 24, display: 'flex', alignItems: 'center', justifyContent: 'center',
                  border: `2px solid ${earned ? m.color : '#4a3422'}`,
                  background: earned ? m.color + '22' : 'transparent',
                  color: earned ? m.color : '#6a5440', fontSize: 13, flexShrink: 0,
                }}
              >{m.icon}</div>
              <span className="forge-pixel" style={{ fontSize: 6, color: earned ? m.color : '#6a5440', whiteSpace: 'nowrap' }}>{t}</span>
            </div>
            {i < TIERS.length - 1 && (
              <div style={{ flex: 1, height: 2, margin: '0 2px', marginBottom: 14, background: i < curIdx ? m.color : '#4a3422' }} />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── ForgeView ────────────────────────────────────────────────────────────────

export function ForgeView() {
  const [mode, setMode] = useState<Mode>('generate');
  const [pendingCount, setPendingCount] = useState(0);

  // Quest input
  const [description, setDescription] = useState('');
  const [keywords, setKeywords] = useState<string[]>([]);
  const [kwDraft, setKwDraft] = useState('');
  const [exampleInput, setExampleInput] = useState('');
  const [apiKey, setApiKeyState] = useState(() => getForgeApiKey());

  // Stage + results
  const [stage, setStage] = useState<Stage>('idle');
  const [error, setError] = useState<string | null>(null);
  const [generated, setGenerated] = useState<ForgeGenerateResponse | null>(null);
  const [audit, setAudit] = useState<ForgeAuditResponse | null>(null);
  const [, setSavedPath] = useState<string | null>(null);
  const [showCode, setShowCode] = useState(false);

  const canGenerate = description.trim().length > 0 && keywords.length > 0 && apiKey.trim().length > 0;
  const canSave = stage === 'generated' && audit?.passed === true && generated != null;
  const isLoading = stage === 'generating' || stage === 'saving';

  function addKeyword(raw: string) {
    const parts = raw.split(/[,\n]+/).map(k => k.trim()).filter(Boolean);
    if (parts.length) setKeywords(prev => [...new Set([...prev, ...parts])]);
    setKwDraft('');
  }
  function onKwKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); if (kwDraft.trim()) addKeyword(kwDraft); }
    else if (e.key === 'Backspace' && !kwDraft && keywords.length) setKeywords(prev => prev.slice(0, -1));
  }

  function handleApiKeyChange(k: string) { setApiKeyState(k); setForgeApiKey(k); }

  async function handleGenerate() {
    if (!canGenerate) return;
    setStage('generating'); setError(null); setGenerated(null); setAudit(null); setSavedPath(null); setShowCode(false);
    try {
      const result = await forgeGenerate(
        { description: description.trim(), keywords, example_input: exampleInput.trim() },
        apiKey.trim(),
      );
      setGenerated(result);
      const auditResult = await forgeAudit(result.code, result.agent_class_name);
      setAudit(auditResult);
      setStage('generated');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setStage('idle');
    }
  }

  async function handleSave() {
    if (!canSave || !generated) return;
    setStage('saving'); setError(null);
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
    setStage('idle'); setGenerated(null); setAudit(null); setSavedPath(null); setError(null); setShowCode(false);
  }

  const labelStyle: React.CSSProperties = {
    fontFamily: 'var(--font-pixel)', fontSize: 8, color: 'var(--ember)',
    display: 'block', marginBottom: 6, marginTop: 2,
  };
  const hintStyle: React.CSSProperties = {
    fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.4,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>

      {/* ── Forge header / mode toggle ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '8px 16px', borderBottom: 'var(--bw)',
        background: 'linear-gradient(180deg, #2a1c12, #1c1510)', flexShrink: 0,
      }}>
        <span className="forge-hammer" style={{ fontSize: 16 }}>⚒</span>
        <span className="forge-pixel" style={{ fontSize: 11, color: 'var(--heat)' }}>THE&nbsp;FORGE</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#c9a784', marginLeft: 2 }}>
          {mode === 'generate' ? 'craft a new micro-agent · BYOK' : 'your forged roster · ascend them to live'}
        </span>

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 0, border: '1px solid var(--ember)', flexShrink: 0 }}>
          {(['generate', 'pending'] as const).map((m, i) => (
            <button key={m} onClick={() => setMode(m)} className="forge-pixel" style={{
              padding: '6px 12px', fontSize: 8,
              background: mode === m ? 'var(--ember)' : 'transparent',
              color: mode === m ? '#fff' : 'var(--heat)',
              border: 'none', borderRight: i === 0 ? '1px solid var(--ember)' : 'none', cursor: 'pointer',
            }}>
              {m === 'generate' ? 'FORGE' : `ROSTER${pendingCount ? ` ${pendingCount}` : ''}`}
            </button>
          ))}
        </div>

        {mode === 'generate' && (stage === 'generated' || stage === 'saved') && (
          <button onClick={handleReset} className="forge-pixel" style={{
            fontSize: 8, padding: '6px 10px', background: 'transparent',
            border: '1px solid var(--ember)', color: 'var(--heat)', cursor: 'pointer',
          }}>
            ⟳ NEW
          </button>
        )}
      </div>

      {/* ── FORGE mode ── */}
      {mode === 'generate' && (
        <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

          {/* LEFT: the crafting bench (guided input) */}
          <div style={{
            width: 330, flexShrink: 0, borderRight: '2px solid var(--forge-line)',
            display: 'flex', flexDirection: 'column', overflow: 'auto',
            background: 'var(--paper-2)',
          }}>
            <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 16 }}>

              <div className="forge-pixel" style={{ fontSize: 9, color: 'var(--text)', borderBottom: '2px solid var(--forge-line)', paddingBottom: 8 }}>
                ⚒ CRAFTING BENCH
              </div>

              {/* 1 · Mission */}
              <div>
                <label style={labelStyle}>1 · THE MISSION</label>
                <div style={hintStyle}>What should your agent hunt for?</div>
                <textarea
                  className="input" value={description} onChange={e => setDescription(e.target.value)}
                  placeholder="Detects open-redirect flaws where a redirect target comes from user input"
                  rows={3} disabled={isLoading}
                  style={{ width: '100%', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 12, boxSizing: 'border-box', marginTop: 6 }}
                />
              </div>

              {/* 2 · Summoning words (chip input) */}
              <div>
                <label style={labelStyle}>2 · SUMMONING WORDS</label>
                <div style={hintStyle}>Phrases that trigger it. Type one and press <b>Enter</b>.</div>
                <div
                  onClick={() => (document.getElementById('kw-draft') as HTMLInputElement | null)?.focus()}
                  style={{
                    marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 5, alignItems: 'center',
                    minHeight: 38, padding: '6px 8px', cursor: 'text',
                    background: 'var(--white)', border: 'var(--bw)', boxShadow: 'inset 1px 1px 0 var(--paper-3)',
                  }}
                >
                  {keywords.map(k => (
                    <span key={k} className="forge-chip">
                      {k}
                      <button onClick={e => { e.stopPropagation(); setKeywords(prev => prev.filter(x => x !== k)); }} disabled={isLoading}>×</button>
                    </span>
                  ))}
                  <input
                    id="kw-draft" value={kwDraft}
                    onChange={e => setKwDraft(e.target.value)} onKeyDown={onKwKey}
                    onBlur={() => kwDraft.trim() && addKeyword(kwDraft)}
                    disabled={isLoading}
                    placeholder={keywords.length ? 'add another…' : 'open redirect scan'}
                    style={{ flex: 1, minWidth: 90, border: 'none', outline: 'none', background: 'transparent',
                      fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)' }}
                  />
                </div>
              </div>

              {/* 3 · Training sample */}
              <div>
                <label style={labelStyle}>3 · TRAINING SAMPLE</label>
                <div style={hintStyle}>Optional — show it an example of what it'll face.</div>
                <textarea
                  className="input" value={exampleInput} onChange={e => setExampleInput(e.target.value)}
                  placeholder={'return redirect(request.args.get("next"))'}
                  rows={2} disabled={isLoading}
                  style={{ width: '100%', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 12, boxSizing: 'border-box', marginTop: 6 }}
                />
              </div>

              {/* Forge key */}
              <div>
                <label style={labelStyle}>⚷ FORGE KEY</label>
                <div style={hintStyle}>Your Anthropic key — stored locally, never sent to our server.</div>
                <input
                  type="password" className="input" value={apiKey}
                  onChange={e => handleApiKeyChange(e.target.value)} placeholder="sk-ant-…" disabled={isLoading}
                  style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: 12, boxSizing: 'border-box', marginTop: 6 }}
                />
              </div>

              <button className="forge-btn forge-glow" onClick={handleGenerate} disabled={!canGenerate || isLoading}
                style={{ marginTop: 2 }}>
                {stage === 'generating' ? '⚒ FORGING…' : '⚒ FORGE AGENT'}
              </button>
              {!canGenerate && !isLoading && (
                <div style={{ ...hintStyle, marginTop: -6, textAlign: 'center' }}>
                  Need a mission, ≥1 summoning word, and a forge key.
                </div>
              )}

              {error && (
                <div style={{ padding: '8px 10px', background: '#3a1414', border: '1px solid #ff5a6a',
                  fontFamily: 'var(--font-mono)', fontSize: 10, color: '#ff9aa6', wordBreak: 'break-all' }}>
                  ✗ {error}
                </div>
              )}
            </div>
          </div>

          {/* RIGHT: the anvil (dark forge interior) */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'auto', background: 'var(--forge-bg)' }}>

            {/* idle */}
            {stage === 'idle' && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 14, padding: 24, minHeight: 240 }}>
                <span className="forge-heat" style={{ fontSize: 52 }}>🔥</span>
                <div className="forge-pixel" style={{ fontSize: 13, color: 'var(--heat)' }}>THE FORGE AWAITS</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#c9a784', textAlign: 'center', maxWidth: 360, lineHeight: 1.6 }}>
                  Fill the bench, then strike the anvil. Claude hammers out a real micro-agent,
                  it's tested by <b style={{ color: 'var(--heat)' }}>trial by fire</b>, and lands in your roster as
                  <span style={{ color: '#ffb400' }}> ◆ UNVERIFIED</span>.
                </div>
              </div>
            )}

            {/* forging animation */}
            {stage === 'generating' && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 18, padding: 24, minHeight: 240 }}>
                <div style={{ position: 'relative', fontSize: 56, display: 'flex', alignItems: 'flex-end', gap: 4 }}>
                  <span className="forge-hammer" style={{ fontSize: 40 }}>🔨</span>
                  <span style={{ fontSize: 50 }}>🟧</span>
                  <div style={{ position: 'absolute', left: 46, top: 6 }}><Sparks n={7} /></div>
                </div>
                <div className="forge-pixel forge-heat" style={{ fontSize: 12, color: 'var(--heat)' }}>⚒ FORGING…</div>
                <div className="forge-bar" style={{ width: 240 }} />
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#c9a784' }}>
                  Claude is hammering out your agent + running the trial…
                </div>
              </div>
            )}

            {/* crafted result */}
            {(stage === 'generated' || stage === 'saving' || stage === 'saved') && generated && (
              <div style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 16 }}>

                {/* item card */}
                <div className="forge-glow" style={{ border: '2px solid var(--ember)', background: 'var(--forge-bg2)', padding: 16 }}>
                  {(() => { const t = agentTypeOf(generated.agent_class_name, keywords); return (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                    <div style={{ width: 48, height: 48, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#120d0a', border: `1px solid ${t.color}` }}>
                      <Creature seed={generated.agent_class_name} color={t.color} size={40} />
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="forge-pixel" style={{ fontSize: 12, color: '#fff' }}>{generated.agent_class_name}</div>
                      <div style={{ fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700, color: t.color, marginTop: 5 }}>{t.emoji} {t.label}</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#c9a784', marginTop: 3 }}>forged by {generated.model_used}</div>
                    </div>
                    <span className="forge-pixel" style={{ fontSize: 8, color: '#1c1510', background: '#ffb400', padding: '4px 7px' }}>◆ UNVERIFIED</span>
                  </div>
                  ); })()}

                  {/* level track */}
                  <div style={{ padding: '6px 4px 2px' }}>
                    <TierTrack current="UNVERIFIED" />
                  </div>

                  {/* summoned by */}
                  <div style={{ marginTop: 12 }}>
                    <div className="forge-pixel" style={{ fontSize: 7, color: 'var(--ember)', marginBottom: 6 }}>SUMMONED BY</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                      {keywords.map(k => <span key={k} className="forge-chip" style={{ paddingRight: 8 }}>{k}</span>)}
                    </div>
                  </div>
                </div>

                {/* TRIAL BY FIRE (audit) */}
                {audit && (
                  <div style={{ border: `2px solid ${audit.passed ? '#5fd38a' : '#ff5a6a'}`, background: 'var(--forge-bg2)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderBottom: '1px solid var(--forge-line)' }}>
                      <span style={{ fontSize: 18 }}>⚔</span>
                      <div className="forge-pixel" style={{ fontSize: 10, color: audit.passed ? '#5fd38a' : '#ff5a6a', flex: 1 }}>
                        TRIAL BY FIRE — {audit.passed ? 'SURVIVED' : 'CRACKED'}
                      </div>
                      {audit.passed && <Sparks n={5} />}
                    </div>
                    <div style={{ padding: '10px 14px' }}>
                      {/* structural checks */}
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: audit.findings.length ? 10 : 0 }}>
                        {Object.entries(audit.structural_checks).map(([key, ok]) => (
                          <span key={key} style={{
                            fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 7px',
                            color: ok ? '#5fd38a' : '#ff9aa6',
                            border: `1px solid ${ok ? '#2e6b46' : '#7d2e3a'}`, background: ok ? '#163521' : '#3a1620',
                          }}>{ok ? '✓' : '✗'} {key}</span>
                        ))}
                      </div>
                      {/* flaws */}
                      {audit.findings.map((f, i) => (
                        <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', padding: '5px 0' }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700, color: SEVERITY_COLOR[f.severity] ?? '#ccc', flexShrink: 0, paddingTop: 1 }}>{f.severity}</span>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#e6d6c8', lineHeight: 1.4 }}>{f.message}</span>
                        </div>
                      ))}
                      {audit.passed && (
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#9ad36a' }}>
                          No flaws — ready to enter your roster.
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* actions */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <button onClick={() => setShowCode(s => !s)} style={{
                    display: 'flex', alignItems: 'center', gap: 5, padding: '6px 10px',
                    background: 'transparent', border: '1px solid var(--forge-line)', color: '#c9a784',
                    fontFamily: 'var(--font-mono)', fontSize: 10, cursor: 'pointer',
                  }}>
                    {showCode ? <ChevronDown size={12} /> : <ChevronRight size={12} />} <Eye size={11} /> code &amp; wiring
                  </button>
                  <div style={{ marginLeft: 'auto' }}>
                    {stage === 'saved' ? (
                      <span className="forge-pixel" style={{ fontSize: 9, color: '#1c1510', background: '#5fd38a', padding: '7px 10px' }}>
                        ✓ ADDED TO ROSTER
                      </span>
                    ) : (
                      <button className="forge-btn" onClick={handleSave} disabled={!canSave} style={{ fontSize: 9, padding: '8px 14px' }}>
                        {stage === 'saving' ? '⚒ SAVING…' : <><Save size={10} style={{ marginRight: 5, verticalAlign: -1 }} />ADD TO ROSTER</>}
                      </button>
                    )}
                  </div>
                </div>
                {!canSave && stage === 'generated' && (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#ff9aa6', marginTop: -8 }}>
                    Fix the flaws above before it can join your roster.
                  </div>
                )}

                {/* code + wiring */}
                {showCode && (
                  <div style={{ border: '1px solid var(--forge-line)' }}>
                    <pre style={{ margin: 0, padding: 14, background: '#120d0a', color: '#d8e0a0',
                      fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.55, whiteSpace: 'pre', overflowX: 'auto', maxHeight: 320 }}>
                      {generated.code}
                    </pre>
                    <div style={{ borderTop: '1px solid var(--forge-line)', background: '#1c1510' }}>
                      <div className="forge-pixel" style={{ fontSize: 7, color: 'var(--ember)', padding: '8px 14px 2px' }}>
                        ⚒ WIRING — HOW TO ASCEND IT
                      </div>
                      <pre style={{ margin: 0, padding: '4px 14px 14px', color: '#c9a784',
                        fontFamily: 'var(--font-mono)', fontSize: 10.5, lineHeight: 1.5, whiteSpace: 'pre', overflowX: 'auto' }}>
                        {generated.router_snippet}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── ROSTER mode ── */}
      {mode === 'pending' && <RosterPanel onCount={setPendingCount} />}
    </div>
  );
}

// ─── TestBench (trial a pending agent before ascending) ────────────────────────

function TestBench({ filename }: { filename: string }) {
  const [open, setOpen] = useState(false);
  const [samples, setSamples] = useState<ForgeTestSample[]>([
    { label: 'vulnerable', content: '', expect_finding: true },
    { label: 'clean', content: '', expect_finding: false },
  ]);
  const [result, setResult] = useState<ForgeTestResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const canRun = samples.some(s => s.content.trim().length > 0);

  const update = (i: number, patch: Partial<ForgeTestSample>) =>
    setSamples(prev => prev.map((s, idx) => (idx === i ? { ...s, ...patch } : s)));
  const addSample = () => setSamples(prev => [...prev, { label: '', content: '', expect_finding: true }]);
  const removeSample = (i: number) => setSamples(prev => prev.filter((_, idx) => idx !== i));

  async function run() {
    setRunning(true); setErr(null); setResult(null);
    try {
      const usable = samples.filter(s => s.content.trim().length > 0)
        .map(s => ({ ...s, label: s.label || (s.expect_finding ? 'vulnerable' : 'clean') }));
      setResult(await forgeTest(filename, usable));
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div style={{ borderTop: '1px solid var(--forge-line)' }}>
      <button onClick={() => setOpen(o => !o)} style={{
        width: '100%', display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px',
        background: 'transparent', border: 'none', cursor: 'pointer', color: '#c9a784',
        fontFamily: 'var(--font-mono)', fontSize: 10, textAlign: 'left',
      }}>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <FlaskConical size={11} style={{ color: 'var(--heat)' }} />
        <span className="forge-pixel" style={{ fontSize: 7, color: 'var(--heat)' }}>TEST BENCH</span>
        <span>— trial it before you ascend</span>
        {result && (
          <span className="forge-pixel" style={{
            marginLeft: 'auto', fontSize: 7, padding: '3px 6px',
            color: result.ready ? '#1c1510' : '#fff', background: result.ready ? '#5fd38a' : '#ff5a6a',
          }}>
            {result.caught}/{result.total} {result.ready ? '✓ PROVEN' : 'NOT READY'}
          </span>
        )}
      </button>

      {open && (
        <div style={{ padding: '0 14px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#c9a784', lineHeight: 1.4 }}>
            Add sample inputs and mark whether each <b>should</b> be flagged. Runs the agent in an isolated sandbox and
            checks it stays stable across input perturbations.
          </div>

          {samples.map((s, i) => (
            <div key={i} style={{ border: '1px solid var(--forge-line)', background: '#120d0a' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', borderBottom: '1px solid var(--forge-line)' }}>
                <button onClick={() => update(i, { expect_finding: !s.expect_finding })} style={{
                  fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700, padding: '3px 7px', cursor: 'pointer', border: 'none',
                  background: s.expect_finding ? '#3a1620' : '#163521', color: s.expect_finding ? '#ff9aa6' : '#5fd38a',
                }}>
                  {s.expect_finding ? '⚠ SHOULD FLAG' : '✓ SHOULD BE CLEAN'}
                </button>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#7a6450' }}>tap to toggle</span>
                <button onClick={() => removeSample(i)} disabled={samples.length <= 1}
                  style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#c9a784', cursor: 'pointer', opacity: samples.length <= 1 ? 0.3 : 1 }}>
                  <X size={12} />
                </button>
              </div>
              <textarea
                value={s.content} onChange={e => update(i, { content: e.target.value })}
                placeholder={s.expect_finding ? 'a sample that SHOULD trip the agent…' : 'a clean sample it should pass…'}
                style={{
                  width: '100%', minHeight: 44, resize: 'vertical', boxSizing: 'border-box', border: 'none', outline: 'none',
                  background: 'transparent', color: '#d8e0a0', fontFamily: 'var(--font-mono)', fontSize: 11, padding: 8,
                }}
              />
            </div>
          ))}

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button onClick={addSample} style={{
              padding: '5px 9px', background: 'transparent', border: '1px solid var(--forge-line)', color: '#c9a784',
              fontFamily: 'var(--font-mono)', fontSize: 10, cursor: 'pointer',
            }}>+ add sample</button>
            <button className="forge-btn" onClick={run} disabled={!canRun || running} style={{ marginLeft: 'auto', fontSize: 8, padding: '8px 13px' }}>
              {running ? '⚗ TESTING…' : '▶ RUN TRIALS'}
            </button>
          </div>

          {err && (
            <div style={{ padding: '6px 10px', background: '#3a1414', border: '1px solid #ff5a6a', fontFamily: 'var(--font-mono)', fontSize: 10, color: '#ff9aa6', whiteSpace: 'pre-wrap' }}>{err}</div>
          )}

          {result && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div className="forge-pixel" style={{
                fontSize: 8, padding: '7px 9px', lineHeight: 1.5,
                color: result.ready ? '#1c1510' : '#fff', background: result.ready ? '#5fd38a' : '#ff5a6a',
              }}>
                {result.ready ? '✓ PROVEN — READY TO ASCEND' : '✗ NOT READY'} · caught {result.caught}/{result.total} · {result.robustness.stable ? 'stable' : 'UNSTABLE'} across {result.robustness.runs} perturbations
              </div>
              {result.samples.map((sr, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', padding: '5px 8px', background: '#120d0a', border: '1px solid var(--forge-line)' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: sr.passed ? '#5fd38a' : '#ff5a6a', flexShrink: 0 }}>{sr.passed ? '✓' : '✗'}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#e6d6c8' }}>
                      {sr.label} — expected {sr.expect_finding ? 'flag' : 'clean'}, agent {sr.flagged ? 'flagged' : 'passed'} (risk {sr.risk_score.toFixed(0)})
                    </div>
                    {sr.error && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#ff9aa6' }}>error: {sr.error}</div>}
                    {sr.findings.length > 0 && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#c9a784' }}>{sr.findings.join(' · ')}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── RosterPanel (pending review + ascend) ─────────────────────────────────────

function RosterPanel({ onCount }: { onCount: (n: number) => void }) {
  const [agents, setAgents] = useState<ForgePendingAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [promoting, setPromoting] = useState<string | null>(null);
  const [promoteErr, setPromoteErr] = useState<Record<string, string>>({});
  const [promoted, setPromoted] = useState<ForgePromoteResponse[]>([]);

  const load = () => {
    setLoading(true); setError(null);
    forgeListPending()
      .then(r => { setAgents(r.agents); onCount(r.agents.length); })
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  async function ascend(filename: string) {
    setPromoting(filename); setPromoteErr(p => ({ ...p, [filename]: '' }));
    try {
      const res = await forgePromote(filename);
      setPromoted(p => [res, ...p]);
      const r = await forgeListPending();
      setAgents(r.agents); onCount(r.agents.length);
    } catch (e: unknown) {
      setPromoteErr(p => ({ ...p, [filename]: e instanceof Error ? e.message : String(e) }));
    } finally {
      setPromoting(null);
    }
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 18, display: 'flex', flexDirection: 'column', gap: 14, background: 'var(--forge-bg)' }}>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span className="forge-pixel" style={{ fontSize: 10, color: 'var(--heat)' }}>⬢ YOUR FORGED ROSTER</span>
        <button onClick={load} disabled={loading} className="forge-pixel" style={{
          fontSize: 7, padding: '5px 9px', background: 'transparent', border: '1px solid var(--ember)', color: 'var(--heat)', cursor: 'pointer', flexShrink: 0,
        }}>⟳ RELOAD</button>
      </div>

      {/* just ascended */}
      {promoted.map(p => (
        <div key={p.agent_name} className="forge-glow" style={{ border: '2px solid #5fd38a', background: 'var(--forge-bg2)', padding: '12px 14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Sparks n={5} />
            <span className="forge-pixel" style={{ fontSize: 9, color: '#5fd38a' }}>{p.agent_name} ASCENDED → ✦ {p.trust_tier}</span>
          </div>
          <div style={{ marginBottom: 8 }}><TierTrack current="VERIFIED" /></div>
          <pre style={{ margin: 0, padding: 10, background: '#120d0a', border: '1px solid var(--forge-line)', color: '#c9a784',
            fontFamily: 'var(--font-mono)', fontSize: 10, lineHeight: 1.5, whiteSpace: 'pre-wrap', overflowX: 'auto' }}>
{`# router.py\n${p.router_edit}\n\n# consensus.py (run_single_perturbed)\n${p.consensus_edit}\n\n# file → ${p.promoted_path}`}
          </pre>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#5fd38a', marginTop: 4 }}>✓ import chain validated in an isolated subprocess</div>
        </div>
      ))}

      {loading && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#c9a784', textAlign: 'center', padding: 24 }}>loading roster…</div>}
      {!loading && error && (
        <div style={{ padding: '10px 12px', background: '#3a1414', border: '1px solid #ff5a6a', fontFamily: 'var(--font-mono)', fontSize: 10, color: '#ff9aa6' }}>{error}</div>
      )}

      {!loading && !error && agents.length === 0 && (
        <div style={{ textAlign: 'center', padding: 40 }}>
          <div style={{ fontSize: 40 }}>🗡️</div>
          <div className="forge-pixel" style={{ fontSize: 10, color: 'var(--heat)', marginTop: 10 }}>EMPTY ROSTER</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#c9a784', marginTop: 6 }}>Forge an agent — it'll appear here to review &amp; ascend.</div>
        </div>
      )}

      {/* roster items */}
      {agents.map(a => {
        const open = expanded === a.filename;
        const busy = promoting === a.filename;
        const err = promoteErr[a.filename];
        return (
          <div key={a.filename} style={{ border: '2px solid var(--forge-line)', background: 'var(--forge-bg2)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px' }}>
              <Creature seed={a.agent_name} color={agentTypeOf(a.agent_name, a.keywords).color} size={30} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="forge-pixel" style={{ fontSize: 9, color: '#fff' }}>{a.agent_name}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#c9a784', marginTop: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {a.filename} · .{a.method_name}()
                </div>
              </div>
              <span className="forge-pixel" style={{ fontSize: 7, color: '#1c1510', background: '#ffb400', padding: '4px 6px' }}>◆ UNVERIFIED</span>
              <span className="forge-pixel" style={{
                fontSize: 7, padding: '4px 6px',
                color: a.audit_passed ? '#5fd38a' : '#ff9aa6',
                border: `1px solid ${a.audit_passed ? '#2e6b46' : '#7d2e3a'}`,
              }}>{a.audit_passed ? '⚔ TRIAL ✓' : '⚔ TRIAL ✗'}</span>

              <button onClick={() => setExpanded(open ? null : a.filename)} style={{
                background: 'none', border: 'none', cursor: 'pointer', color: '#c9a784',
                display: 'flex', alignItems: 'center', gap: 3, fontFamily: 'var(--font-mono)', fontSize: 10,
              }}>{open ? <ChevronDown size={12} /> : <ChevronRight size={12} />} code</button>

              <button onClick={() => ascend(a.filename)} disabled={!a.audit_passed || busy}
                className="forge-btn" style={{
                  fontSize: 8, padding: '7px 11px',
                  ...(a.audit_passed ? {} : { filter: 'grayscale(.7) brightness(.8)', cursor: 'default', opacity: .6 }),
                }}
                title={a.audit_passed ? 'Wire into the live router + dispatch (→ VERIFIED)' : 'Fix the trial flaws first'}>
                {busy ? '⚒ ASCENDING…' : '▲ ASCEND'}
              </button>
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, padding: '0 14px 10px' }}>
              {a.keywords.map(k => <span key={k} className="forge-chip" style={{ paddingRight: 8 }}>{k}</span>)}
            </div>

            <TestBench filename={a.filename} />

            {err && (
              <div style={{ margin: '0 14px 10px', padding: '6px 10px', background: '#3a1414', border: '1px solid #ff5a6a', fontFamily: 'var(--font-mono)', fontSize: 10, color: '#ff9aa6', whiteSpace: 'pre-wrap' }}>{err}</div>
            )}
            {open && (
              <pre style={{ margin: 0, padding: 12, borderTop: '1px solid var(--forge-line)', background: '#120d0a', color: '#d8e0a0',
                fontFamily: 'var(--font-mono)', fontSize: 10.5, lineHeight: 1.5, whiteSpace: 'pre', overflowX: 'auto' }}>{a.code}</pre>
            )}
          </div>
        );
      })}

      {!loading && agents.length > 0 && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#c9a784', lineHeight: 1.5 }}>
          <b style={{ color: 'var(--heat)' }}>Ascend</b> moves the file out of <code>pending/</code>, wires it into the live router +
          dispatch, and validates the whole import chain in a subprocess — rolling back on any failure.
        </div>
      )}
    </div>
  );
}
