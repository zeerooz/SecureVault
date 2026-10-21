import { createContext } from 'react';

import type { UserSummary } from '../api/types';

export type VaultStatus = 'locked' | 'unlocked';

export interface AuthState {
  status: VaultStatus;
  user: UserSummary | null;
  vaultKey: CryptoKey | null;
}

export interface AuthContextValue extends AuthState {
  register: (email: string, masterPassword: string) => Promise<void>;
  /** Resolves to true when a second factor is still needed. */
  login: (email: string, masterPassword: string, twoFactorCode?: string) => Promise<boolean>;
  logout: () => Promise<void>;
  changeMasterPassword: (currentPassword: string, newPassword: string) => Promise<void>;
  refreshUser: () => Promise<void>;
}

// Kept apart from the provider component so that the module holding the
// provider exports components only, which is what React Fast Refresh needs.
export const AuthContext = createContext<AuthContextValue | null>(null);
