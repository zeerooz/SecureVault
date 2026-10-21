import { useEffect, useState } from 'react';

interface SecretValueProps {
  value: string;
  label: string;
  onCopied?: (label: string) => void;
}

/**
 * A secret stays hidden until someone asks for it, and hides itself again
 * shortly after. The timer is a convenience against shoulder-surfing, not a
 * security control — anything on screen has already been decrypted in memory.
 */
const AUTO_HIDE_MS = 20_000;

export function SecretValue({ value, label, onCopied }: SecretValueProps) {
  // Storing which value is revealed, rather than a boolean, means switching to
  // another item hides the new secret automatically — no reset effect needed.
  const [revealedValue, setRevealedValue] = useState<string | null>(null);
  const revealed = revealedValue === value;

  useEffect(() => {
    if (!revealed) {
      return;
    }

    const timer = window.setTimeout(() => setRevealedValue(null), AUTO_HIDE_MS);
    return () => window.clearTimeout(timer);
  }, [revealed]);

  const setRevealed = (next: boolean) => setRevealedValue(next ? value : null);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      onCopied?.(label);
    } catch {
      onCopied?.('Copying needs clipboard permission');
    }
  }

  return (
    <div className="secret">
      <code className={`secret-value ${revealed ? 'revealed' : 'sealed'}`}>
        {revealed ? value : '•'.repeat(Math.min(value.length || 12, 24))}
      </code>

      <button
        type="button"
        className="btn-secondary"
        onClick={() => setRevealed(!revealed)}
        aria-pressed={revealed}
      >
        {revealed ? 'Hide' : 'Show'}
      </button>

      <button type="button" className="btn-secondary" onClick={copy}>
        Copy
      </button>
    </div>
  );
}
