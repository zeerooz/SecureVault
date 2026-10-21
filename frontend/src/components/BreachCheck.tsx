import { useState } from 'react';

import { checkPasswordBreach } from '../crypto/hibp';

type State =
  | { kind: 'idle' }
  | { kind: 'checking' }
  | { kind: 'clean' }
  | { kind: 'breached'; count: number }
  | { kind: 'failed'; message: string };

export function BreachCheck({ password }: { password: string }) {
  const [state, setState] = useState<State>({ kind: 'idle' });

  async function run() {
    setState({ kind: 'checking' });

    try {
      const result = await checkPasswordBreach(password);
      setState(result.breached ? { kind: 'breached', count: result.count } : { kind: 'clean' });
    } catch (cause) {
      setState({ kind: 'failed', message: cause instanceof Error ? cause.message : 'Check failed.' });
    }
  }

  return (
    <div className="stack">
      <div className="row">
        <button type="button" className="btn-secondary" onClick={run} disabled={!password || state.kind === 'checking'}>
          {state.kind === 'checking' ? 'Checking…' : 'Check for breaches'}
        </button>

        {state.kind === 'clean' ? <span className="tag tag-ok">Not found in any known breach</span> : null}
        {state.kind === 'breached' ? (
          <span className="tag tag-bad">Found {state.count.toLocaleString()} times</span>
        ) : null}
      </div>

      {state.kind === 'breached' ? (
        <p className="notice notice-error">
          This password appears in public breach data. Replace it here and anywhere else you used it.
        </p>
      ) : null}

      {state.kind === 'failed' ? <p className="notice notice-error">{state.message}</p> : null}

      <p className="inline-note">
        Your password is never sent. The browser hashes it and sends the first five characters of that hash to Have I
        Been Pwned, then compares the returned list locally.
      </p>
    </div>
  );
}
