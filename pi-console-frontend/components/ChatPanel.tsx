"use client";

import { useRef } from "react";

interface ChatPanelProps {
  messages: { role: "user" | "assistant"; text: string }[];
  onSend: (text: string) => void;
  loading?: boolean;
}

export default function ChatPanel({ messages, onSend, loading }: ChatPanelProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <div className="flex flex-col gap-3 p-4 bg-[var(--card)] rounded-lg border border-[var(--border)] h-full">
      <h2 className="text-lg font-bold text-[var(--foreground)]">Chat / Agent Mode</h2>
      <p className="text-xs text-[var(--muted-foreground)]">
        Natural language is translated into ExplicitCompositionRequest. All proposals require your explicit approval.
      </p>
      <div className="flex-1 overflow-auto flex flex-col gap-2 min-h-[200px]">
        {messages.map((m, i) => (
          <div
            key={i}
            className={`p-2 rounded text-sm max-w-[85%] ${
              m.role === "user"
                ? "self-end bg-[var(--accent)] text-[var(--accent-foreground)]"
                : "self-start bg-[var(--secondary)] text-[var(--secondary-foreground)]"
            }`}
          >
            <pre className="whitespace-pre-wrap font-mono text-xs">{m.text}</pre>
          </div>
        ))}
        {loading && (
          <div className="self-start bg-[var(--secondary)] text-[var(--muted-foreground)] px-3 py-1 rounded text-xs">
            Translating...
          </div>
        )}
      </div>
      <div className="flex gap-2">
        <input
          ref={inputRef}
          className="flex-1 bg-[var(--input)] text-[var(--foreground)] rounded px-3 py-2 text-sm border border-[var(--border)]"
          placeholder="Describe what you want to compose..."
          onKeyDown={(e) => {
            if (e.key === "Enter" && inputRef.current?.value) {
              onSend(inputRef.current.value);
              inputRef.current.value = "";
            }
          }}
        />
        <button
          onClick={() => {
            if (inputRef.current?.value) {
              onSend(inputRef.current.value);
              inputRef.current.value = "";
            }
          }}
          disabled={loading}
          className="bg-[var(--primary)] text-[var(--primary-foreground)] px-4 py-2 rounded text-sm hover:opacity-90 disabled:opacity-50"
        >
          Send
        </button>
      </div>
    </div>
  );
}
