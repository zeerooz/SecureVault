import { useCallback, useEffect, useMemo, useState } from 'react';

import { api } from '../api/client';
import { VaultItemTypes, type VaultItemResponse, type VaultItemType } from '../api/types';
import { ItemEditor, type EditorValue } from '../components/ItemEditor';
import { SecretValue } from '../components/SecretValue';
import { decryptItem, encryptItem, type VaultItemData } from '../crypto/vault';
import { useAuth } from '../state/useAuth';

/** A server record paired with its decrypted contents, held only in memory. */
interface DecryptedItem {
  id: string;
  type: VaultItemType;
  revision: number;
  updatedAt: string;
  data: VaultItemData;
  /** Set when this particular blob could not be decrypted. */
  error?: string;
}

const EMPTY_DRAFT: EditorValue = {
  type: VaultItemTypes.Login,
  data: { name: '', username: '', password: '', url: '', notes: '' },
};

const TYPE_LABELS: Record<number, string> = {
  [VaultItemTypes.Login]: 'Login',
  [VaultItemTypes.SecureNote]: 'Note',
  [VaultItemTypes.Card]: 'Card',
};

export function VaultPage({ notify }: { notify: (message: string) => void }) {
  const { vaultKey } = useAuth();

  const [items, setItems] = useState<DecryptedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [creating, setCreating] = useState(false);
  const [saving, setSaving] = useState(false);

  const decryptAll = useCallback(
    async (records: VaultItemResponse[]): Promise<DecryptedItem[]> => {
      if (!vaultKey) {
        return [];
      }

      return Promise.all(
        records.map(async (record) => {
          try {
            return {
              id: record.id,
              type: record.type,
              revision: record.revision,
              updatedAt: record.updatedAt,
              data: await decryptItem(vaultKey, record.encryptedData),
            };
          } catch {
            // One unreadable blob must not take down the whole list.
            return {
              id: record.id,
              type: record.type,
              revision: record.revision,
              updatedAt: record.updatedAt,
              data: { name: 'Unreadable item' },
              error: 'This item could not be decrypted with your current key.',
            };
          }
        }),
      );
    },
    [vaultKey],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      setItems(await decryptAll(await api.listItems()));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not load the vault.');
    } finally {
      setLoading(false);
    }
  }, [decryptAll]);

  useEffect(() => {
    void load();
  }, [load]);

  /*
    Search runs entirely here, over already-decrypted items. The server has no
    searchable copy of anything, which is the direct cost of it holding only
    ciphertext — and the reason the whole vault is fetched up front.
  */
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();

    if (!needle) {
      return items;
    }

    return items.filter((item) =>
      [item.data.name, item.data.username, item.data.url, item.data.notes]
        .filter(Boolean)
        .some((field) => field!.toLowerCase().includes(needle)),
    );
  }, [items, query]);

  const selected = items.find((item) => item.id === selectedId) ?? null;

  async function save(value: EditorValue) {
    if (!vaultKey) {
      return;
    }

    setSaving(true);
    setError(null);

    try {
      const encryptedData = await encryptItem(vaultKey, value.data);

      if (creating) {
        const created = await api.createItem({ type: value.type, encryptedData });
        setSelectedId(created.id);
        notify('Item saved');
      } else if (selected) {
        await api.updateItem(selected.id, {
          type: value.type,
          encryptedData,
          revision: selected.revision,
        });
        notify('Item saved');
      }

      setEditing(false);
      setCreating(false);
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not save the item.');
    } finally {
      setSaving(false);
    }
  }

  async function remove(item: DecryptedItem) {
    if (!window.confirm(`Delete "${item.data.name}"? This cannot be undone.`)) {
      return;
    }

    try {
      await api.deleteItem(item.id);
      setSelectedId(null);
      notify('Item deleted');
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not delete the item.');
    }
  }

  function startCreating() {
    setCreating(true);
    setEditing(true);
    setSelectedId(null);
  }

  return (
    <div className="vault">
      <div className="vault-list">
        <div className="vault-search">
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search your vault"
            aria-label="Search your vault"
          />
          <button type="button" className="btn-primary" onClick={startCreating}>
            Add item
          </button>
        </div>

        <div className="vault-items">
          {loading ? <p className="empty">Decrypting your vault…</p> : null}

          {!loading && items.length === 0 ? (
            <div className="empty">
              <p>Your vault is empty.</p>
              <button type="button" className="btn-secondary" onClick={startCreating}>
                Add your first item
              </button>
            </div>
          ) : null}

          {!loading && items.length > 0 && visible.length === 0 ? (
            <p className="empty">Nothing matches “{query}”.</p>
          ) : null}

          {visible.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`vault-item ${item.id === selectedId ? 'selected' : ''}`}
              onClick={() => {
                setSelectedId(item.id);
                setEditing(false);
                setCreating(false);
              }}
            >
              <span className="vault-item-name">{item.data.name}</span>
              <span className="vault-item-meta">
                {item.data.username || TYPE_LABELS[item.type] || 'Item'}
              </span>
            </button>
          ))}
        </div>
      </div>

      <div className="vault-detail">
        {error ? <p className="notice notice-error">{error}</p> : null}

        {editing ? (
          <ItemEditor
            // Remounts on a different item, which resets the form cleanly.
            key={creating ? 'new' : (selected?.id ?? 'none')}
            initial={
              creating || !selected
                ? EMPTY_DRAFT
                : { type: selected.type, data: selected.data }
            }
            saving={saving}
            onSave={save}
            onCancel={() => {
              setEditing(false);
              setCreating(false);
            }}
          />
        ) : null}

        {!editing && !selected ? (
          <div className="empty">
            <p>Select an item to see it, or add a new one.</p>
          </div>
        ) : null}

        {!editing && selected ? (
          <div className="stack-lg">
            <div className="pane-head">
              <div>
                <h1>{selected.data.name}</h1>
                <p className="pane-sub">
                  {TYPE_LABELS[selected.type]} &middot; updated{' '}
                  {new Date(selected.updatedAt).toLocaleString()}
                </p>
              </div>

              <div className="row">
                <button type="button" className="btn-secondary" onClick={() => setEditing(true)}>
                  Edit
                </button>
                <button type="button" className="btn-danger" onClick={() => remove(selected)}>
                  Delete
                </button>
              </div>
            </div>

            {selected.error ? <p className="notice notice-error">{selected.error}</p> : null}

            <div className="stack">
              {selected.data.username ? (
                <div className="field">
                  <span>Username</span>
                  <SecretValue value={selected.data.username} label="Username" onCopied={notify} />
                </div>
              ) : null}

              {selected.data.password ? (
                <div className="field">
                  <span>Password</span>
                  <SecretValue value={selected.data.password} label="Password" onCopied={notify} />
                </div>
              ) : null}

              {selected.data.url ? (
                <div className="field">
                  <span>Website</span>
                  <a href={selected.data.url} target="_blank" rel="noreferrer noopener">
                    {selected.data.url}
                  </a>
                </div>
              ) : null}

              {selected.data.notes ? (
                <div className="field">
                  <span>Notes</span>
                  <p style={{ whiteSpace: 'pre-wrap' }}>{selected.data.notes}</p>
                </div>
              ) : null}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
