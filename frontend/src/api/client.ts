import {
  ApiError,
  type AuditLogResponse,
  type LoginResponse,
  type PreloginResponse,
  type ProblemDetails,
  type RefreshResponse,
  type SessionResponse,
  type TwoFactorRequiredResponse,
  type TwoFactorSetupResponse,
  type UserSummary,
  type VaultItemResponse,
  type VaultItemType,
} from './types';

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';

/**
 * Tokens live in module scope, never in localStorage or sessionStorage.
 *
 * That is a deliberate trade of convenience for safety: a cross-site scripting
 * bug on this origin can read anything in web storage, and a refresh token
 * sitting there is a persistent account takeover. In memory it dies with the
 * tab. The cost is that reloading the page signs you out, which for a password
 * manager is the right default anyway — the vault key cannot survive a reload
 * either, because it is only ever derived from the master password.
 */
let accessToken: string | null = null;
let refreshToken: string | null = null;

/** Set by the auth layer so a failed refresh can tear down the session. */
let onSessionLost: (() => void) | null = null;

export function setTokens(tokens: { accessToken: string; refreshToken: string } | null): void {
  accessToken = tokens?.accessToken ?? null;
  refreshToken = tokens?.refreshToken ?? null;
}

export function setSessionLostHandler(handler: (() => void) | null): void {
  onSessionLost = handler;
}

export function hasSession(): boolean {
  return accessToken !== null;
}

/**
 * Serialises refresh attempts. Without this, five parallel requests that all
 * see a 401 would each rotate the refresh token, and four of them would be
 * treated by the server as token reuse — which revokes the whole family and
 * logs the user out.
 */
let refreshInFlight: Promise<boolean> | null = null;

async function refreshSession(): Promise<boolean> {
  if (!refreshToken) {
    return false;
  }

  refreshInFlight ??= (async () => {
    try {
      const response = await fetch(`${BASE_URL}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      });

      if (!response.ok) {
        return false;
      }

      const body = (await response.json()) as RefreshResponse;
      accessToken = body.accessToken;
      refreshToken = body.refreshToken;
      return true;
    } catch {
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

async function toError(response: Response): Promise<ApiError> {
  let message = `Request failed (HTTP ${response.status}).`;

  try {
    const problem = (await response.json()) as ProblemDetails;
    message = problem.detail ?? problem.title ?? message;
  } catch {
    // A non-JSON error body is not worth surfacing verbatim.
  }

  return new ApiError(response.status, message);
}

async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');

  if (init.body !== undefined) {
    headers.set('Content-Type', 'application/json');
  }

  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }

  const response = await fetch(`${BASE_URL}${path}`, { ...init, headers });

  if (response.status === 401 && retry && refreshToken) {
    if (await refreshSession()) {
      return request<T>(path, init, false);
    }

    setTokens(null);
    onSessionLost?.();
  }

  if (!response.ok) {
    throw await toError(response);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

const json = (body: unknown): RequestInit => ({ body: JSON.stringify(body) });

export const api = {
  prelogin: (email: string) =>
    request<PreloginResponse>('/api/auth/prelogin', { method: 'POST', ...json({ email }) }),

  register: (payload: {
    email: string;
    authHash: string;
    kdfSalt: string;
    kdfIterations: number;
    protectedVaultKey: string;
  }) => request<LoginResponse>('/api/auth/register', { method: 'POST', ...json(payload) }),

  login: (payload: { email: string; authHash: string; twoFactorCode?: string }) =>
    request<LoginResponse | TwoFactorRequiredResponse>('/api/auth/login', {
      method: 'POST',
      ...json(payload),
    }),

  logout: () =>
    request<void>('/api/auth/logout', { method: 'POST', ...json({ refreshToken: refreshToken ?? '' }) }),

  me: () => request<UserSummary>('/api/auth/me'),

  listItems: () => request<VaultItemResponse[]>('/api/vault/items'),

  createItem: (payload: { type: VaultItemType; encryptedData: string }) =>
    request<VaultItemResponse>('/api/vault/items', { method: 'POST', ...json(payload) }),

  updateItem: (id: string, payload: { type: VaultItemType; encryptedData: string; revision: number }) =>
    request<VaultItemResponse>(`/api/vault/items/${id}`, { method: 'PUT', ...json(payload) }),

  deleteItem: (id: string) => request<void>(`/api/vault/items/${id}`, { method: 'DELETE' }),

  listSessions: () => request<SessionResponse[]>('/api/sessions'),

  revokeSession: (id: string) => request<void>(`/api/sessions/${id}`, { method: 'DELETE' }),

  revokeOtherSessions: () => request<void>('/api/sessions/others', { method: 'DELETE' }),

  auditLog: (take = 50) => request<AuditLogResponse[]>(`/api/audit?take=${take}`),

  setupTwoFactor: () => request<TwoFactorSetupResponse>('/api/account/2fa/setup', { method: 'POST' }),

  enableTwoFactor: (code: string) =>
    request<{ recoveryCodes: string[] }>('/api/account/2fa/enable', { method: 'POST', ...json({ code }) }),

  disableTwoFactor: (code: string) =>
    request<void>('/api/account/2fa/disable', { method: 'POST', ...json({ code }) }),

  changeMasterPassword: (payload: {
    currentAuthHash: string;
    newAuthHash: string;
    newKdfSalt: string;
    newKdfIterations: number;
    newProtectedVaultKey: string;
  }) => request<void>('/api/account/master-password', { method: 'POST', ...json(payload) }),
};
