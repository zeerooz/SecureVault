import { useState } from 'react';
import { Link } from 'react-router-dom';

import { estimateTypedEntropy, strengthFromEntropy } from '../crypto/generator';
import { useAuth } from '../state/useAuth';

const MINIMUM_LENGTH = 12;

export function RegisterPage() {
  const { register } = useAuth();

  const [email, setEmail] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const bits = estimateTypedEntropy(masterPassword);
  const strength = strengthFromEntropy(bits);
  const tooShort = masterPassword.length > 0 && masterPassword.length < MINIMUM_LENGTH;
  const mismatch = confirmation.length > 0 && confirmation !== masterPassword;

  const canSubmit =
    !busy && acknowledged && masterPassword.length >= MINIMUM_LENGTH && masterPassword === confirmation;

  async function submit(event: React.FormEvent) {
    event.preventDefault();

    if (!canSubmit) {
      return;
    }

    setBusy(true);
    setError(null);

    try {
      await register(email, masterPassword);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not create the account.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="entry">
      <aside className="entry-aside">
        <p className="entry-mark">SecureVault</p>

        <h1 className="entry-claim">One password you remember.</h1>

        <p className="entry-lede">
          Your master password unlocks everything else, and it is the one thing no one can recover for you. Choose
          something long that you will not forget.
        </p>

        <div className="ledger">
          <div className="ledger-row">
            <span>Key derivation</span>
            <span className="value">PBKDF2, 600k rounds</span>
          </div>
          <div className="ledger-row">
            <span>Item encryption</span>
            <span className="value">AES-256-GCM</span>
          </div>
          <div className="ledger-row">
            <span>Password reset</span>
            <span className="value never">not possible</span>
          </div>
        </div>
      </aside>

      <form className="entry-form" onSubmit={submit}>
        <h2>Create your vault</h2>

        <label className="field">
          <span>Email</span>
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            autoComplete="username"
            required
          />
        </label>

        <label className="field">
          <span>Master password</span>
          <input
            type="password"
            value={masterPassword}
            onChange={(event) => setMasterPassword(event.target.value)}
            autoComplete="new-password"
            required
          />
          {masterPassword ? (
            <>
              <div className="meter" aria-hidden="true">
                <div
                  className={`meter-fill ${strength}`}
                  style={{ width: `${Math.min(100, (bits / 120) * 100)}%` }}
                />
              </div>
              <span className="field-hint">
                Roughly {bits} bits of entropy &middot; {strength}
              </span>
            </>
          ) : (
            <span className="field-hint">At least {MINIMUM_LENGTH} characters. A short phrase beats a short word.</span>
          )}
          {tooShort ? <span className="field-hint">Use at least {MINIMUM_LENGTH} characters.</span> : null}
        </label>

        <label className="field">
          <span>Confirm master password</span>
          <input
            type="password"
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            autoComplete="new-password"
            required
          />
          {mismatch ? <span className="field-hint">The two entries do not match.</span> : null}
        </label>

        <label className="checkline">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />
          I understand that losing this password means losing the vault.
        </label>

        {error ? <p className="notice notice-error">{error}</p> : null}

        <button type="submit" className="btn-primary" disabled={!canSubmit}>
          {busy ? 'Creating…' : 'Create vault'}
        </button>

        <p className="field-hint">
          Already have a vault? <Link to="/login">Sign in</Link>
        </p>
      </form>
    </div>
  );
}
