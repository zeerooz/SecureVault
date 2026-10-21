import { useCallback, useState } from 'react';

import {
  DEFAULT_GENERATOR_OPTIONS,
  entropyBits,
  generatePassword,
  strengthFromEntropy,
  type GeneratorOptions,
} from '../crypto/generator';

interface PasswordGeneratorProps {
  onUse: (password: string) => void;
}

export function PasswordGenerator({ onUse }: PasswordGeneratorProps) {
  const [options, setOptions] = useState<GeneratorOptions>(DEFAULT_GENERATOR_OPTIONS);
  const [error, setError] = useState<string | null>(null);

  // Seeded during the first render and replaced only in response to an action.
  // Generating inside an effect would produce a throwaway password on mount.
  const [password, setPassword] = useState(() => generatePassword(DEFAULT_GENERATOR_OPTIONS));

  const regenerate = useCallback((next: GeneratorOptions) => {
    try {
      setPassword(generatePassword(next));
      setError(null);
    } catch (cause) {
      setPassword('');
      setError(cause instanceof Error ? cause.message : 'Could not generate a password.');
    }
  }, []);

  /** Every option change immediately produces a password matching the new rules. */
  function apply(change: Partial<GeneratorOptions>) {
    const next = { ...options, ...change };
    setOptions(next);
    regenerate(next);
  }

  const bits = entropyBits(options);
  const strength = strengthFromEntropy(bits);

  function toggle(key: keyof GeneratorOptions) {
    apply({ [key]: !options[key] } as Partial<GeneratorOptions>);
  }

  return (
    <div className="stack">
      <div className="secret">
        <code className="secret-value revealed">{password || '—'}</code>
        <button type="button" className="btn-secondary" onClick={() => regenerate(options)}>
          New
        </button>
        <button type="button" className="btn-primary" onClick={() => onUse(password)} disabled={!password}>
          Use
        </button>
      </div>

      {error ? <p className="notice notice-error">{error}</p> : null}

      <div className="meter" aria-hidden="true">
        <div className={`meter-fill ${strength}`} style={{ width: `${Math.min(100, (bits / 140) * 100)}%` }} />
      </div>
      <p className="inline-note">
        {bits} bits of entropy &middot; {strength}
      </p>

      <label className="field">
        <span>Length: {options.length}</span>
        <input
          type="range"
          min={8}
          max={64}
          value={options.length}
          onChange={(event) => apply({ length: Number(event.target.value) })}
        />
      </label>

      <div className="grid-two">
        <label className="checkline">
          <input type="checkbox" checked={options.lowercase} onChange={() => toggle('lowercase')} />
          Lowercase
        </label>
        <label className="checkline">
          <input type="checkbox" checked={options.uppercase} onChange={() => toggle('uppercase')} />
          Uppercase
        </label>
        <label className="checkline">
          <input type="checkbox" checked={options.digits} onChange={() => toggle('digits')} />
          Digits
        </label>
        <label className="checkline">
          <input type="checkbox" checked={options.symbols} onChange={() => toggle('symbols')} />
          Symbols
        </label>
        <label className="checkline">
          <input type="checkbox" checked={options.excludeAmbiguous} onChange={() => toggle('excludeAmbiguous')} />
          Skip lookalike characters
        </label>
      </div>
    </div>
  );
}
