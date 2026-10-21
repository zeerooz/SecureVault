import { useCallback, useEffect, useState } from 'react';
import QRCode from 'qrcode';

import { api } from '../api/client';
import type { AuditLogResponse, SessionResponse } from '../api/types';
import { useAuth } from '../state/useAuth';

const AUDIT_LABELS: Record<string, string> = {
  RegisterSucceeded: 'Account created',
  LoginSucceeded: 'Signed in',
  LoginFailed: 'Failed sign-in',
  LoginLockedOut: 'Blocked, account locked',
  TwoFactorChallenged: 'Two-factor requested',
  TwoFactorFailed: 'Wrong two-factor code',
  TwoFactorEnabled: 'Two-factor turned on',
  TwoFactorDisabled: 'Two-factor turned off',
  TokenRefreshed: 'Session renewed',
  TokenReuseDetected: 'Reused session token blocked',
  LoggedOut: 'Signed out',
  SessionRevoked: 'Session revoked',
  MasterPasswordChanged: 'Master password changed',
  VaultItemCreated: 'Item added',
  VaultItemUpdated: 'Item changed',
  VaultItemDeleted: 'Item deleted',
  RecoveryCodeUsed: 'Recovery code used',
};

export function SettingsPage({ notify }: { notify: (message: string) => void }) {
  const { user, refreshUser, changeMasterPassword } = useAuth();

  const [sessions, setSessions] = useState<SessionResponse[]>([]);
  const [audit, setAudit] = useState<AuditLogResponse[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [sessionList, auditList] = await Promise.all([api.listSessions(), api.auditLog(30)]);
      setSessions(sessionList);
      setAudit(auditList);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not load your account activity.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="pane">
      <div className="pane-head">
        <div>
          <h1>Settings</h1>
          <p className="pane-sub">Signed in as {user?.email}</p>
        </div>
      </div>

      {error ? <p className="notice notice-error">{error}</p> : null}

      <div className="stack-lg">
        <TwoFactorPanel
          enabled={user?.twoFactorEnabled ?? false}
          notify={notify}
          onChanged={async () => {
            await refreshUser();
            await load();
          }}
        />

        <MasterPasswordPanel onChange={changeMasterPassword} />

        <SessionsPanel
          sessions={sessions}
          notify={notify}
          onChanged={load}
        />

        <section className="panel">
          <h2 className="panel-title">Recent activity</h2>
          <p className="panel-note">
            Every security-relevant action on your account. A sign-in you do not recognise is the earliest warning you
            will get.
          </p>

          <div className="table-scroll" style={{ marginTop: 14 }}>
            <table className="records">
              <thead>
                <tr>
                  <th>Event</th>
                  <th>From</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((entry) => (
                  <tr key={entry.id}>
                    <td className="primary">{AUDIT_LABELS[entry.event] ?? entry.event}</td>
                    <td className="wrap">{entry.ipAddress ?? '—'}</td>
                    <td>{new Date(entry.createdAt).toLocaleString()}</td>
                  </tr>
                ))}
                {audit.length === 0 ? (
                  <tr>
                    <td colSpan={3}>Nothing recorded yet.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}

function TwoFactorPanel({
  enabled,
  notify,
  onChanged,
}: {
  enabled: boolean;
  notify: (message: string) => void;
  onChanged: () => Promise<void>;
}) {
  const [secret, setSecret] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function startSetup() {
    setBusy(true);
    setError(null);

    try {
      const setup = await api.setupTwoFactor();
      setSecret(setup.secret);
      setQr(await QRCode.toDataURL(setup.otpAuthUri, { margin: 1, width: 180 }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not start setup.');
    } finally {
      setBusy(false);
    }
  }

  async function enable() {
    setBusy(true);
    setError(null);

    try {
      const result = await api.enableTwoFactor(code);
      setRecoveryCodes(result.recoveryCodes);
      setSecret(null);
      setQr(null);
      setCode('');
      notify('Two-factor authentication is on');
      await onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not turn on two-factor authentication.');
    } finally {
      setBusy(false);
    }
  }

  async function disable() {
    setBusy(true);
    setError(null);

    try {
      await api.disableTwoFactor(code);
      setCode('');
      notify('Two-factor authentication is off');
      await onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not turn off two-factor authentication.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel stack">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h2 className="panel-title">Two-factor authentication</h2>
        <span className={`tag ${enabled ? 'tag-ok' : ''}`}>{enabled ? 'On' : 'Off'}</span>
      </div>

      <p className="panel-note">
        A second factor protects your account, not your data. Your vault is encrypted with your master password, so a
        code cannot unlock anything on its own — but it does stop someone who has only stolen your password.
      </p>

      {error ? <p className="notice notice-error">{error}</p> : null}

      {recoveryCodes ? (
        <div className="stack">
          <p className="notice notice-ok">
            Save these recovery codes somewhere safe. Each works once, and this is the only time they are shown.
          </p>
          <div className="codes">
            {recoveryCodes.map((recoveryCode) => (
              <span key={recoveryCode}>{recoveryCode}</span>
            ))}
          </div>
          <div className="row row-end">
            <button type="button" className="btn-secondary" onClick={() => setRecoveryCodes(null)}>
              I have saved them
            </button>
          </div>
        </div>
      ) : null}

      {!enabled && !secret && !recoveryCodes ? (
        <div className="row">
          <button type="button" className="btn-primary" onClick={startSetup} disabled={busy}>
            Set up two-factor authentication
          </button>
        </div>
      ) : null}

      {secret ? (
        <div className="stack">
          <p className="panel-note">Scan this with your authenticator app, then enter the code it shows.</p>
          {qr ? (
            <div className="qr">
              <img src={qr} alt="QR code for your authenticator app" width={180} height={180} />
            </div>
          ) : null}
          <p className="inline-note">
            Cannot scan? Enter this key manually: <code>{secret}</code>
          </p>

          <label className="field" style={{ maxWidth: 220 }}>
            <span>Code from your app</span>
            <input
              type="text"
              className="mono-input"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              placeholder="123456"
            />
          </label>

          <div className="row">
            <button type="button" className="btn-primary" onClick={enable} disabled={busy || code.length < 6}>
              Turn on
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => {
                setSecret(null);
                setQr(null);
              }}
              disabled={busy}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      {enabled ? (
        <div className="stack">
          <label className="field" style={{ maxWidth: 220 }}>
            <span>Code from your app</span>
            <input
              type="text"
              className="mono-input"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              placeholder="123456"
            />
          </label>
          <div className="row">
            <button type="button" className="btn-danger" onClick={disable} disabled={busy || code.length < 6}>
              Turn off two-factor authentication
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
}

function MasterPasswordPanel({
  onChange,
}: {
  onChange: (currentPassword: string, newPassword: string) => Promise<void>;
}) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      await onChange(current, next);
      // On success the server revokes every session, so this page unmounts.
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not change the master password.');
      setBusy(false);
    }
  }

  const canSubmit = !busy && current.length > 0 && next.length >= 12 && next === confirmation;

  return (
    <section className="panel">
      <h2 className="panel-title">Master password</h2>
      <p className="panel-note">
        Your items are encrypted with a vault key, not with your master password directly, so changing it re-wraps one
        small key rather than re-encrypting everything. You will be signed out everywhere.
      </p>

      <form className="stack" style={{ marginTop: 14, maxWidth: 380 }} onSubmit={submit}>
        <label className="field">
          <span>Current master password</span>
          <input
            type="password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            autoComplete="current-password"
          />
        </label>

        <label className="field">
          <span>New master password</span>
          <input
            type="password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
            autoComplete="new-password"
          />
          <span className="field-hint">At least 12 characters.</span>
        </label>

        <label className="field">
          <span>Confirm new master password</span>
          <input
            type="password"
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            autoComplete="new-password"
          />
        </label>

        {error ? <p className="notice notice-error">{error}</p> : null}

        <div className="row">
          <button type="submit" className="btn-primary" disabled={!canSubmit}>
            {busy ? 'Changing…' : 'Change master password'}
          </button>
        </div>
      </form>
    </section>
  );
}

function SessionsPanel({
  sessions,
  notify,
  onChanged,
}: {
  sessions: SessionResponse[];
  notify: (message: string) => void;
  onChanged: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);

  async function revoke(id: string) {
    setBusy(true);
    await api.revokeSession(id);
    notify('Session revoked');
    await onChanged();
    setBusy(false);
  }

  async function revokeOthers() {
    setBusy(true);
    await api.revokeOtherSessions();
    notify('Signed out everywhere else');
    await onChanged();
    setBusy(false);
  }

  return (
    <section className="panel">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h2 className="panel-title">Where you are signed in</h2>
        <button
          type="button"
          className="btn-secondary"
          onClick={revokeOthers}
          disabled={busy || sessions.length < 2}
        >
          Sign out everywhere else
        </button>
      </div>

      <div className="table-scroll" style={{ marginTop: 14 }}>
        <table className="records">
          <thead>
            <tr>
              <th>Device</th>
              <th>Address</th>
              <th>Last used</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {sessions.map((session) => (
              <tr key={session.id}>
                <td className="primary wrap">
                  {session.userAgent ?? 'Unknown device'}
                  {session.isCurrent ? ' · this device' : ''}
                </td>
                <td className="wrap">{session.ipAddress ?? '—'}</td>
                <td>{new Date(session.lastSeenAt).toLocaleString()}</td>
                <td>
                  {session.isCurrent ? null : (
                    <button type="button" className="btn-ghost" onClick={() => revoke(session.id)} disabled={busy}>
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {sessions.length === 0 ? (
              <tr>
                <td colSpan={4}>No active sessions.</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
