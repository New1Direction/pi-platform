'use client';

import { useEffect, useId, useRef } from 'react';
import { useTheme } from 'next-themes';

interface MermaidProps {
  chart: string;
}

export function Mermaid({ chart }: MermaidProps) {
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  const { resolvedTheme } = useTheme();

  useEffect(() => {
    if (!ref.current) return;

    import('mermaid').then((m) => {
      m.default.initialize({
        startOnLoad: false,
        theme: resolvedTheme === 'dark' ? 'dark' : 'neutral',
        fontFamily: 'inherit',
        fontSize: 14,
        flowchart: { curve: 'basis', padding: 20 },
        sequence: { actorMargin: 60, messageMargin: 40 },
      });

      const safeId = `mermaid-${id.replace(/:/g, '')}`;

      m.default
        .render(safeId, chart)
        .then(({ svg }) => {
          if (ref.current) ref.current.innerHTML = svg;
        })
        .catch(console.error);
    });
  }, [chart, resolvedTheme, id]);

  return (
    <div
      ref={ref}
      className="my-6 flex justify-center overflow-x-auto rounded-lg border bg-muted/30 p-4"
    />
  );
}
