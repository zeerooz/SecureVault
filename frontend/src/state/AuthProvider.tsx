import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';

import { api, setSessionLostHandler, setTokens } from '../api/client';
import { isTwoFactorRequired } from '../api/types';
import { AuthContext, type AuthContextValue, type AuthState } from './authContext';
import { DEFAULT_KDF_ITERATIONS, deriveAuthHash, deriveMasterKey, generateKdfSalt } from '../crypto/kdf';
import { generateVaultKey, unwrapVaultKey, wrapVaultKey } from '../crypto/vault';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: 'locked', user: null, vaultKey: null });

  // The master key is held only for as long as the vault is unlocked, and only
  // so the master password can be changed without asking for it twice. It is
  // never written to storage.
  const [masterKey, setMasterKey] = useState<Uint8Array | null>(null);

  const lock = useCallback(() => {
    masterKey?.fill(0);
    setMasterKey(null);
    setTokens(null);
    setState({ status: 'locked', user: null, vaultKey: null });
  }, [masterKey]);

  useEffect(() => {
    // A refresh that cannot be rescued drops straight back to the lock screen.
    setSessionLostHandler(lock);
    return () => setSessionLostHandler(null);
  }, [lock]);

  const register = useCallback(async (email: string, masterPassword: string) => {
    const kdfSalt = generateKdfSalt();
    const derived = await deriveMasterKey(masterPassword, kdfSalt, DEFAULT_KDF_ITERATIONS);
    const authHash = await deriveAuthHash(derived, masterPassword);

    // A fresh random vault key, wrapped under the master password. Every item
    // is encrypted with this key, which is why changing the master password
    // later re-wraps one small blob instead of rewriting the whole vault.
    const vaultKey = await generateVaultKey();
    const protectedVaultKey = await wrapVaultKey(vaultKey, derived);

    const session = await api.register({
      email,
      authHash,
      kdfSalt,
      kdfIterations: DEFAULT_KDF_ITERATIONS,
      protectedVaultKey,
    });

    setTokens(session);
    setMasterKey(derived);
    setState({ status: 'unlocked', user: session.user, vaultKey });
  }, []);

  const login = useCallback(async (email: string, masterPassword: string, twoFactorCode?: string) => {
    const { kdfSalt, kdfIterations } = await api.prelogin(email);
    const derived = await deriveMasterKey(masterPassword, kdfSalt, kdfIterations);
    const authHash = await deriveAuthHash(derived, masterPassword);

    const result = await api.login({ email, authHash, twoFactorCode });

    if (isTwoFactorRequired(result)) {
      derived.fill(0);
      return true;
    }

    setTokens(result);

    // Unwrapping is what actually proves the master password was right: the
    // server only ever saw a hash of a hash of it.
    const vaultKey = await unwrapVaultKey(result.protectedVaultKey, derived);

    setMasterKey(derived);
    setState({ status: 'unlocked', user: result.user, vaultKey });
    return false;
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // The local session is torn down either way.
    }

    lock();
  }, [lock]);

  const changeMasterPassword = useCallback(
    async (currentPassword: string, newPassword: string) => {
      if (!state.user || !state.vaultKey || !masterKey) {
        throw new Error('Unlock the vault before changing the master password.');
      }

      const currentAuthHash = await deriveAuthHash(masterKey, currentPassword);

      const newKdfSalt = generateKdfSalt();
      const newMasterKey = await deriveMasterKey(newPassword, newKdfSalt, DEFAULT_KDF_ITERATIONS);
      const newAuthHash = await deriveAuthHash(newMasterKey, newPassword);

      // Same vault key, new wrapper. No item is touched.
      const newProtectedVaultKey = await wrapVaultKey(state.vaultKey, newMasterKey);

      await api.changeMasterPassword({
        currentAuthHash,
        newAuthHash,
        newKdfSalt,
        newKdfIterations: DEFAULT_KDF_ITERATIONS,
        newProtectedVaultKey,
      });

      // The server revoked every session, including this one.
      lock();
    },
    [lock, masterKey, state.user, state.vaultKey],
  );

  const refreshUser = useCallback(async () => {
    const user = await api.me();
    setState((previous) => ({ ...previous, user }));
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ ...state, register, login, logout, changeMasterPassword, refreshUser }),
    [state, register, login, logout, changeMasterPassword, refreshUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
