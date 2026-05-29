"use client";

import { useRef, useEffect } from "react";
import { Send, Bot, User, Terminal, Sparkles, AlertCircle } from "lucide-react";

interface ChatPanelProps {
  messages: { role: "user" | "assistant"; text: string }[];
  onSend: (text: string) => void;
  loading?: boolean;
}

export default function ChatPanel({ messages, onSend, loading }: ChatPanelProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const streamEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to the bottom of the chat stream
  useEffect(() => {
    streamEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  const handleSend = () => {
    if (inputRef.current?.value.trim()) {
      onSend(inputRef.current.value.trim());
      inputRef.current.value = "";
    }
  };

  return (
    <div className="flex flex-col h-full glass-panel overflow-hidden">
      {/* Chat Panel Header */}
      <div className="px-6 py-4 border-b border-[var(--border)] flex items-center justify-between bg-zinc-950/20">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-[var(--primary)]/10 text-[var(--primary)] rounded-lg">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-1.5">
              Security Copilot <Sparkles className="w-3.5 h-3.5 text-[var(--primary)] animate-pulse" />
            </h2>
            <p className="text-[10px] text-[var(--muted-foreground)]">
              Propose micro-agent compositions via natural language
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-emerald-950/20 border border-emerald-500/20 text-emerald-400 text-[10px] font-mono">
          <Terminal className="w-3 h-3" /> SECURE TUNNEL
        </div>
      </div>

      {/* Info Warning */}
      <div className="px-6 py-2.5 bg-yellow-500/5 border-b border-[var(--border)] text-[10px] text-yellow-200/80 flex items-center gap-2">
        <AlertCircle className="w-3.5 h-3.5 text-yellow-400 shrink-0" />
        <span>All compositions generated via chat are simulated and require your manual approval before deployment.</span>
      </div>

      {/* Messages Stream */}
      <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-4">
        {messages.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
            <div className="p-4 bg-[var(--primary)]/5 rounded-full border border-[var(--primary)]/10 mb-3 text-[var(--primary)]">
              <Bot className="w-8 h-8" />
            </div>
            <h3 className="text-sm font-medium text-zinc-300">No active communication</h3>
            <p className="text-xs text-zinc-500 max-w-sm mt-1">
              "Compose a validation pipeline checking GCP IAM policy risks and S3 bucket encryption keys."
            </p>
          </div>
        ) : (
          messages.map((m, i) => (
            <div
              key={i}
              className={`flex gap-3 max-w-[85%] ${
                m.role === "user" ? "self-end flex-row-reverse" : "self-start"
              }`}
            >
              {/* Avatar Icon */}
              <div
                className={`w-7 h-7 rounded-full shrink-0 flex items-center justify-center text-xs border ${
                  m.role === "user"
                    ? "bg-[var(--accent)]/10 border-[var(--accent)]/20 text-[var(--accent)]"
                    : "bg-[var(--primary)]/10 border-[var(--primary)]/20 text-[var(--primary)]"
                }`}
              >
                {m.role === "user" ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              {/* Message Bubble */}
              <div
                className={`p-4 rounded-xl text-sm border shadow-lg leading-relaxed ${
                  m.role === "user"
                    ? "bg-blue-600/10 border-blue-500/20 text-zinc-100 rounded-tr-none"
                    : "bg-zinc-950/50 border-[var(--border)] text-zinc-200 rounded-tl-none font-mono text-xs"
                }`}
              >
                {m.role === "user" ? (
                  <p className="whitespace-pre-wrap">{m.text}</p>
                ) : (
                  <pre className="whitespace-pre-wrap overflow-x-auto text-[11px] font-mono leading-5 text-emerald-400 bg-zinc-950/70 p-3 rounded-lg border border-zinc-800/80">
                    {m.text}
                  </pre>
                )}
              </div>
            </div>
          ))
        )}

        {/* Loading Spinner */}
        {loading && (
          <div className="flex gap-3 max-w-[80%] self-start">
            <div className="w-7 h-7 rounded-full shrink-0 flex items-center justify-center text-xs border bg-[var(--primary)]/10 border-[var(--primary)]/20 text-[var(--primary)] animate-pulse">
              <Bot className="w-4 h-4 animate-spin [animation-duration:3s]" />
            </div>
            <div className="p-3 bg-zinc-950/30 border border-[var(--border)] rounded-xl rounded-tl-none text-[11px] text-[var(--muted-foreground)] flex items-center gap-2">
              <span className="flex gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--primary)] animate-bounce" style={{ animationDelay: "0ms" }} />
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--primary)] animate-bounce" style={{ animationDelay: "150ms" }} />
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--primary)] animate-bounce" style={{ animationDelay: "300ms" }} />
              </span>
              <span>Copilot is parsing request...</span>
            </div>
          </div>
        )}

        <div ref={streamEndRef} />
      </div>

      {/* Input controls container */}
      <div className="p-4 border-t border-[var(--border)] bg-zinc-950/30">
        <div className="flex gap-2 relative items-center">
          <input
            ref={inputRef}
            type="text"
            className="flex-1 bg-zinc-900/50 text-white rounded-lg px-4 py-3 text-sm border border-[var(--border)] placeholder-zinc-500 focus:outline-none"
            placeholder="Describe what you want to compose..."
            onKeyDown={(e) => {
              if (e.key === "Enter") handleSend();
            }}
          />
          <button
            onClick={handleSend}
            disabled={loading}
            className="bg-[var(--primary)] text-white px-5 py-3 rounded-lg text-sm font-medium hover:opacity-90 active:scale-95 disabled:opacity-50 flex items-center gap-1.5 cursor-pointer shadow-md"
          >
            <Send className="w-4 h-4" aria-hidden="true" /> Send
          </button>
        </div>
      </div>
    </div>
  );
}
