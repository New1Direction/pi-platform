import { useState, useRef, useCallback } from 'react';

type Props = {
  tip: React.ReactNode;
  children: React.ReactNode;
  delay?: number;
  pos?: 'top' | 'bottom' | 'right' | 'left';
  wrapStyle?: React.CSSProperties;
};

export function Tooltip({ tip, children, delay = 480, pos = 'bottom', wrapStyle }: Props) {
  const [visible, setVisible] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const enter = useCallback(() => {
    timer.current = setTimeout(() => setVisible(true), delay);
  }, [delay]);

  const leave = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    setVisible(false);
  }, []);

  const box: React.CSSProperties = {
    position: 'absolute',
    zIndex: 9999,
    background: '#ffffe1',
    border: '1px solid #000',
    padding: '5px 9px',
    fontFamily: 'var(--font-ui)',
    fontSize: 11,
    fontWeight: 400,
    color: '#000',
    whiteSpace: 'pre-line',
    maxWidth: 240,
    lineHeight: 1.6,
    pointerEvents: 'none',
    boxShadow: '2px 2px 0 rgba(0,0,0,0.18)',
    textAlign: 'left',
    userSelect: 'none',
  };

  switch (pos) {
    case 'bottom':
      box.top = 'calc(100% + 4px)'; box.left = '50%'; box.transform = 'translateX(-50%)'; break;
    case 'top':
      box.bottom = 'calc(100% + 4px)'; box.left = '50%'; box.transform = 'translateX(-50%)'; break;
    case 'right':
      box.left = 'calc(100% + 6px)'; box.top = 0; break;
    case 'left':
      box.right = 'calc(100% + 6px)'; box.top = 0; break;
  }

  return (
    <div
      style={{ position: 'relative', display: 'inline-flex', ...wrapStyle }}
      onMouseEnter={enter}
      onMouseLeave={leave}
    >
      {children}
      {visible && tip && <div style={box}>{tip}</div>}
    </div>
  );
}
