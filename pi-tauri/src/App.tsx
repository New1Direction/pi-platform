import { useState, useEffect, useCallback } from 'react';
import { Activity, Database, Grid3x3, Hammer, Shield, Zap, Bot, Wifi, WifiOff, Wrench } from 'lucide-react';
import { Tooltip } from './components/Tooltip';
import { createSession, getTenantId, getLedgerSummary, listCapabilities } from './lib/api';
import type { LedgerSummaryResponse } from './types';
import { LedgerView }   from './views/LedgerView';
import { RegistryView } from './views/RegistryView';
import { BuilderView }  from './views/BuilderView';
import { ComposeView }  from './views/ComposeView';
import { ChatView }     from './views/ChatView';
import { QuotaView }    from './views/QuotaView';
import { ForgeView }    from './views/ForgeView';
import { AiAssistant }  from './components/AiAssistant';

type Tab = 'ledger' | 'agents' | 'builder' | 'compose' | 'quota' | 'forge';

type NavItem = {
  id: Tab;
  label: string;
  icon: React.ReactNode;
  color: string;
  tabColor: string;
  titleClass: string;
  tip: string;
};

const NAV: NavItem[] = [
  {
    id: 'ledger', label: 'Ledger',
    icon: <Database size={14} />, color: '#1133aa', tabColor: '#2244cc', titleClass: '',
    tip: 'Ledger\nHash-chained audit log of every agent execution.\nView traces, risk scores, and anomaly alerts.',
  },
  {
    id: 'agents', label: 'Agents',
    icon: <Grid3x3 size={14} />, color: '#1a6633', tabColor: '#228844', titleClass: 'registry',
    tip: 'Agents\nBrowse all 248 security micro-agents.\nFilter by trust tier, runtime, or capability.',
  },
  {
    id: 'builder', label: 'Builder',
    icon: <Zap size={14} />, color: '#006677', tabColor: '#0088aa', titleClass: 'ai',
    tip: 'Agent Builder\nChoose a workflow template, describe your goal,\nthen simulate and run in one click.',
  },
  {
    id: 'compose', label: 'Compose',
    icon: <Wrench size={13} />, color: '#994400', tabColor: '#bb5500', titleClass: 'compose',
    tip: 'Compose\nAdvanced raw DAG editor.\nManually configure runtimes, operations, and multi-node pipelines.',
  },
  {
    id: 'quota', label: 'Quota',
    icon: <Activity size={14} />, color: '#660099', tabColor: '#7733bb', titleClass: 'quota',
    tip: 'Quota\nMonitor API usage, rate limits,\nand resource consumption across tenants.',
  },
  {
    id: 'forge', label: 'Forge',
    icon: <Hammer size={13} />, color: '#7a2900', tabColor: '#aa3a00', titleClass: 'forge',
    tip: 'Agent Forge\nAI-assisted micro-agent generator.\nDescribe what you need — Claude writes the code.\nAgents land in pending/ as UNVERIFIED.',
  },
];

// Classic Win98-style folder SVG — desktop-sized (bigger than sidebar version)
function FolderIcon({ color, tabColor, icon, active }: {
  color: string; tabColor: string; icon: React.ReactNode; active: boolean;
}) {
  return (
    <div style={{ position: 'relative', width: 56, height: 46, filter: active ? 'brightness(1.15)' : 'brightness(1)' }}>
      <svg viewBox="0 0 56 44" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}>
        {/* Drop shadow */}
        <rect x="4" y="13" width="50" height="29" rx="2.5" fill="rgba(0,0,0,0.38)" />
        {/* Folder body */}
        <rect x="1" y="11" width="50" height="29" rx="2.5" fill={color} />
        {/* Top highlight stripe */}
        <rect x="1" y="11" width="50" height="5" rx="2.5" fill="rgba(255,255,255,0.24)" />
        {/* Bottom shadow stripe */}
        <rect x="1" y="36" width="50" height="4" rx="1.5" fill="rgba(0,0,0,0.22)" />
        {/* Folder tab */}
        <rect x="1" y="4" width="20" height="10" rx="2.5" fill={tabColor} />
        {/* Tab-to-body seam */}
        <rect x="1" y="11" width="20" height="4" fill={tabColor} />
      </svg>
      {/* Icon overlay */}
      <div style={{
        position: 'absolute', bottom: 7, right: 8,
        color: 'rgba(255,255,255,0.9)',
        filter: 'drop-shadow(0 1px 2px rgba(0,0,0,0.6))',
      }}>
        {icon}
      </div>
    </div>
  );
}

// A single desktop icon (folder + label), floating on the teal wallpaper
function DesktopIcon({ nav, active, onClick }: {
  nav: NavItem; active: boolean; onClick: () => void;
}) {
  return (
    <Tooltip tip={nav.tip} pos="right" wrapStyle={{ display: 'block' }}>
      <button
        onClick={onClick}
        style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          gap: 6, padding: '6px 8px',
          background: active ? 'rgba(0,0,160,0.45)' : 'transparent',
          border: active
            ? '1px dotted rgba(255,255,255,0.9)'
            : '1px dotted transparent',
          cursor: 'pointer', width: 80,
          transition: 'background 80ms',
        } as React.CSSProperties}
        onMouseEnter={e => {
          if (!active) (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.1)';
        }}
        onMouseLeave={e => {
          if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent';
        }}
      >
        <FolderIcon color={nav.color} tabColor={nav.tabColor} icon={nav.icon} active={active} />
        <span style={{
          fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 400,
          color: '#fff',
          textShadow: '1px 1px 2px #000, 0 0 4px #000',
          textAlign: 'center', lineHeight: 1.25,
          display: 'block', maxWidth: 72,
          padding: '1px 3px',
          background: active ? 'rgba(0,0,128,0.7)' : 'transparent',
        }}>{nav.label}</span>
      </button>
    </Tooltip>
  );
}

function Clock() {
  const [time, setTime] = useState(
    new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  );
  useEffect(() => {
    const id = setInterval(
      () => setTime(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })),
      10000
    );
    return () => clearInterval(id);
  }, []);
  return <span className="taskbar-clock">{time}</span>;
}

function StatsWidget({ summary, agentCount }: { summary: LedgerSummaryResponse | null; agentCount: number }) {
  return (
    <div className="widget">
      <div className="widget-title">PC STATS</div>
      <div className="widget-body">
        {([
          ['AGENTS',    agentCount > 0 ? `${agentCount}` : '…'],
          ['TRACES',    summary ? String(summary.total_traces) : '…'],
          ['SUCCESS',   summary ? `${(summary.success_rate * 100).toFixed(0)}%` : '…'],
          ['AVG RISK',  summary ? summary.avg_risk_score.toFixed(1) : '…'],
          ['ANOMALIES', summary ? String(summary.anomalies_count) : '…'],
        ] as [string, string][]).map(([k, v]) => (
          <div key={k} className="widget-row">
            <span className="widget-key">{k}:</span>
            <span className="widget-val" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [tab, setTab]               = useState<Tab>('ledger');
  const [composeMode, setComposeMode] = useState<'builder' | 'copilot'>('builder');
  const [sessionId, setSessionId]   = useState<string | null>(null);
  const [status, setStatus]         = useState<'connecting' | 'ok' | 'error'>('connecting');
  const [aiOpen, setAiOpen]         = useState(false);
  const [summary, setSummary]       = useState<LedgerSummaryResponse | null>(null);
  const [agentCount, setAgentCount] = useState(0);

  useEffect(() => {
    createSession(getTenantId())
      .then(r => { setSessionId(r.session_id); setStatus('ok'); })
      .catch(() => setStatus('error'));
    getLedgerSummary().then(setSummary).catch(() => {});
    listCapabilities(1).then(r => setAgentCount(r.total)).catch(() => {});
  }, []);

  const toggleAi = useCallback(() => setAiOpen(o => !o), []);

  useEffect(() => {
    const handle = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'i') { e.preventDefault(); toggleAi(); }
    };
    window.addEventListener('keydown', handle);
    return () => window.removeEventListener('keydown', handle);
  }, [toggleAi]);

  const activeNav = NAV.find(n => n.id === tab)!;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>

      {/* ─── Desktop ─── */}
      <div style={{ flex: 1, overflow: 'hidden', position: 'relative' }}>

        {/* ── Desktop icons — float on wallpaper, absolutely positioned ── */}
        <div style={{
          position: 'absolute', top: 10, left: 8, zIndex: 2,
          display: 'flex', flexDirection: 'column', gap: 6,
          // pointer-events handled per-icon
        }}>
          {NAV.map(n => (
            <DesktopIcon key={n.id} nav={n} active={tab === n.id} onClick={() => setTab(n.id)} />
          ))}

          {/* Gap between nav and utility icons */}
          <div style={{ height: 10 }} />

          {/* AI / Ask AI icon */}
          <DesktopIcon
            nav={{ id: 'quota', label: 'Ask AI', icon: <Bot size={16} />, color: '#005566', tabColor: '#007799', titleClass: 'ai', tip: 'Ask AI\nOpen the PI Assistant chat panel.\nBYOK — uses your Anthropic API key.\nCtrl+I to toggle.' }}
            active={aiOpen}
            onClick={toggleAi}
          />
        </div>

        {/* ── Windows + widgets — positioned to the right of the icon column ── */}
        <div style={{
          position: 'absolute', inset: 0,
          paddingLeft: 96, paddingTop: 8, paddingRight: 8, paddingBottom: 4,
          display: 'flex', gap: 8,
          pointerEvents: 'none', // let icons sit above
        }}>
          {/* ── Main window ── */}
          <div className="win" style={{ flex: 1, minWidth: 0, pointerEvents: 'all' }}>

          {/* Title bar */}
          <div className={`win-title ${activeNav.titleClass}`}>
            <span className="win-title-icon">
              <Shield size={9} style={{ color: activeNav.color }} />
            </span>
            <span style={{ marginLeft: 2 }}>PI Console — {activeNav.label}</span>
            <div className="win-title-btns">
              <Tooltip tip="Minimize" pos="bottom"><span className="win-title-btn">_</span></Tooltip>
              <Tooltip tip="Maximize" pos="bottom"><span className="win-title-btn">□</span></Tooltip>
              <Tooltip tip="Close"    pos="bottom"><span className="win-title-btn">✕</span></Tooltip>
            </div>
          </div>

          {/* Menu bar */}
          <div className="menubar">
            {['File', 'Edit', 'View', 'Agents', 'Help'].map(m => (
              <button key={m} className="menu-item">{m}</button>
            ))}
            {/* Compose sub-tabs inline in menu bar */}
            {tab === 'compose' && (
              <>
                <div className="toolbar-sep" />
                {(['builder', 'copilot'] as const).map(mode => (
                  <button
                    key={mode}
                    className="menu-item"
                    onClick={() => setComposeMode(mode)}
                    style={{
                      background: composeMode === mode
                        ? 'linear-gradient(to right, var(--title-from), var(--title-to))'
                        : undefined,
                      color: composeMode === mode ? '#fff' : undefined,
                    }}
                  >
                    {mode === 'builder' ? 'Builder' : 'Copilot'}
                  </button>
                ))}
              </>
            )}
          </div>

          {/* Content */}
          <div className="win-content">
            {tab === 'ledger'   && <LedgerView />}
            {tab === 'agents'   && <RegistryView />}
            {tab === 'builder'  && <BuilderView sessionId={sessionId} />}
            {tab === 'compose' && composeMode === 'builder' && <ComposeView sessionId={sessionId} />}
            {tab === 'compose' && composeMode === 'copilot' && <ChatView sessionId={sessionId} />}
            {tab === 'quota'    && <QuotaView />}
            {tab === 'forge'    && <ForgeView />}
          </div>
        </div>

          {/* ── Right widgets ── */}
          <div style={{ width: 158, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 7, pointerEvents: 'all' }}>
            <StatsWidget summary={summary} agentCount={agentCount} />

            <div className="widget">
              <div className="widget-title">Connection</div>
              <div className="widget-body">
                <div className="widget-row">
                  {status === 'ok'
                    ? <><Wifi size={10} style={{ color: '#226633' }} /><span style={{ color: '#226633', fontWeight: 700, fontSize: 11 }}>ONLINE</span></>
                    : status === 'error'
                      ? <><WifiOff size={10} style={{ color: '#cc0022' }} /><span style={{ color: '#cc0022', fontWeight: 700, fontSize: 11 }}>OFFLINE</span></>
                      : <span style={{ fontSize: 11, color: '#886600' }}>Connecting…</span>}
                </div>
                {sessionId && (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--chrome-dd)', marginTop: 4, wordBreak: 'break-all' }}>
                    {getTenantId()} · {sessionId.slice(0, 18)}…
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ── AI panel ── */}
          {aiOpen && (
            <div style={{ pointerEvents: 'all' }}>
              <AiAssistant onClose={() => setAiOpen(false)} />
            </div>
          )}
        </div>{/* end windows+widgets absolute div */}
      </div>{/* end desktop */}

      {/* ─── Taskbar ─── */}
      <div className="taskbar">
        <Tooltip tip={'PI Console\nClick to open the start menu.\nDouble-click icons to open windows.'} pos="top">
          <button className="start-btn">
            <Shield size={11} strokeWidth={3} style={{ color: '#000080' }} />
            <span style={{ fontFamily: 'var(--font-pixel)', fontSize: 9 }}>Start</span>
          </button>
        </Tooltip>
        <div className="toolbar-sep" />
        <div className="taskbar-window">
          <Shield size={9} style={{ flexShrink: 0 }} />
          PI Console — {activeNav.label}
        </div>
        <div style={{ marginLeft: 8, display: 'flex', gap: 4, alignItems: 'center', fontFamily: 'var(--font-ui)', fontSize: 10 }}>
          {status === 'ok'
            ? <span style={{ color: '#226633', display: 'flex', gap: 3, alignItems: 'center' }}><Wifi size={10} /> Online</span>
            : <span style={{ color: '#cc0022', display: 'flex', gap: 3, alignItems: 'center' }}><WifiOff size={10} /> Offline</span>}
        </div>
        <Clock />
      </div>
    </div>
  );
}
