import { useState } from 'react';
import { Link } from 'react-router-dom';

import { useAuth } from '../state/useAuth';

export function LoginPage() {
  const { login } = useAuth();

  const [email, setEmail] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [needsSecondFactor, setNeedsSecondFactor] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const requiresTwoFactor = await login(email, masterPassword, twoFactorCode || undefined);

      if (requiresTwoFactor) {
        setNeedsSecondFactor(true);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not sign in.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="entry">
      <aside className="entry-aside">
        <p className="entry-mark">SecureVault</p>

        <h1 className="entry-claim">Your passwords stay yours.</h1>

        <p className="entry-lede">
          Everything is encrypted in your browser before it is sent. The server stores ciphertext it has no way to
          read, and your master password never leaves this device.
        </p>

        <div className="ledger">
          <div className="ledger-row">
            <span>Master password</span>
            <span className="value never">never sent</span>
          </div>
          <div className="ledger-row">
            <span>Encryption key</span>
            <span className="value never">never sent</span>
          </div>
          <div className="ledger-row">
            <span>Login proof</span>
            <span className="value">PBKDF2 → Argon2id</span>
          </div>
          <div className="ledger-row">
            <span>Stored items</span>
            <span className="value">AES-256-GCM</span>
          </div>
        </div>
      </aside>

      <form className="entry-form" onSubmit={submit}>
        <h2>Sign in</h2>

        <label className="field">
          <span>Email</span>
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            autoComplete="username"
            required
            disabled={needsSecondFactor}
          />
        </label>

        <label className="field">
          <span>Master password</span>
          <input
            type="password"
            value={masterPassword}
            onChange={(event) => setMasterPassword(event.target.value)}
            autoComplete="current-password"
            required
            disabled={needsSecondFactor}
          />
        </label>

        {needsSecondFactor ? (
          <label className="field">
            <span>Authentication code</span>
            <input
              type="text"
              className="mono-input"
              value={twoFactorCode}
              onChange={(event) => setTwoFactorCode(event.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              autoFocus
              required
            />
            <span className="field-hint">Enter the code from your authenticator app, or a recovery code.</span>
          </label>
        ) : null}

        {error ? <p className="notice notice-error">{error}</p> : null}

        <button type="submit" className="btn-primary" disabled={busy}>
          {busy ? 'Unlocking…' : needsSecondFactor ? 'Verify and unlock' : 'Unlock vault'}
        </button>

        <p className="field-hint">
          Deriving your key takes a moment — that slowness is deliberate, and it is what makes guessing your master
          password expensive.
        </p>

        <p className="field-hint">
          No account yet? <Link to="/register">Create one</Link>
        </p>
      </form>
    </div>
  );
}
