import { useState } from 'react';

import type { VaultItemType } from '../api/types';
import { VaultItemTypes } from '../api/types';
import type { VaultItemData } from '../crypto/vault';
import { BreachCheck } from './BreachCheck';
import { PasswordGenerator } from './PasswordGenerator';

export interface EditorValue {
  type: VaultItemType;
  data: VaultItemData;
}

interface ItemEditorProps {
  initial: EditorValue;
  saving: boolean;
  onSave: (value: EditorValue) => void;
  onCancel: () => void;
}

/**
 * The caller gives this component a `key` tied to the item being edited, so
 * switching items remounts it with fresh state. That is cheaper and less
 * error-prone than copying props into state inside an effect.
 */
export function ItemEditor({ initial, saving, onSave, onCancel }: ItemEditorProps) {
  const [type, setType] = useState<VaultItemType>(initial.type);
  const [data, setData] = useState<VaultItemData>(initial.data);
  const [showGenerator, setShowGenerator] = useState(false);

  function set<K extends keyof VaultItemData>(key: K, value: VaultItemData[K]) {
    setData((current) => ({ ...current, [key]: value }));
  }

  function submit(event: React.FormEvent) {
    event.preventDefault();

    if (!data.name.trim()) {
      return;
    }

    onSave({ type, data: { ...data, name: data.name.trim() } });
  }

  const isLogin = type === VaultItemTypes.Login;

  return (
    <form className="stack-lg" onSubmit={submit}>
      <div className="stack">
        <label className="field">
          <span>Name</span>
          <input
            type="text"
            value={data.name}
            onChange={(event) => set('name', event.target.value)}
            placeholder="Company bank login"
            required
            autoFocus
          />
        </label>

        <label className="field">
          <span>Type</span>
          <select value={type} onChange={(event) => setType(Number(event.target.value) as VaultItemType)}>
            <option value={VaultItemTypes.Login}>Login</option>
            <option value={VaultItemTypes.SecureNote}>Note</option>
            <option value={VaultItemTypes.Card}>Card</option>
          </select>
        </label>

        {isLogin ? (
          <>
            <label className="field">
              <span>Username</span>
              <input
                type="text"
                value={data.username ?? ''}
                onChange={(event) => set('username', event.target.value)}
                autoComplete="off"
              />
            </label>

            <label className="field">
              <span>Password</span>
              <input
                type="text"
                className="mono-input"
                value={data.password ?? ''}
                onChange={(event) => set('password', event.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </label>

            <div className="row">
              <button type="button" className="btn-ghost" onClick={() => setShowGenerator((shown) => !shown)}>
                {showGenerator ? 'Hide generator' : 'Generate a password'}
              </button>
            </div>

            {showGenerator ? (
              <div className="panel">
                <PasswordGenerator
                  onUse={(password) => {
                    set('password', password);
                    setShowGenerator(false);
                  }}
                />
              </div>
            ) : null}

            {data.password ? <BreachCheck password={data.password} /> : null}

            <label className="field">
              <span>Website</span>
              <input
                type="text"
                value={data.url ?? ''}
                onChange={(event) => set('url', event.target.value)}
                placeholder="https://"
                autoComplete="off"
              />
            </label>
          </>
        ) : null}

        <label className="field">
          <span>Notes</span>
          <textarea value={data.notes ?? ''} onChange={(event) => set('notes', event.target.value)} />
        </label>
      </div>

      <div className="row row-end">
        <button type="button" className="btn-secondary" onClick={onCancel} disabled={saving}>
          Cancel
        </button>
        <button type="submit" className="btn-primary" disabled={saving || !data.name.trim()}>
          {saving ? 'Saving…' : 'Save'}
        </button>
      </div>
    </form>
  );
}
