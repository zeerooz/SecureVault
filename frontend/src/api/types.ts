export type VaultItemType = 0 | 1 | 2;

export const VaultItemTypes = {
  Login: 0 as VaultItemType,
  SecureNote: 1 as VaultItemType,
  Card: 2 as VaultItemType,
};

export interface PreloginResponse {
  kdfType: number;
  kdfIterations: number;
  kdfSalt: string;
}

export interface UserSummary {
  id: string;
  email: string;
  twoFactorEnabled: boolean;
  createdAt: string;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  expiresInSeconds: number;
  protectedVaultKey: string;
  user: UserSummary;
}

export interface TwoFactorRequiredResponse {
  requiresTwoFactor: true;
}

export function isTwoFactorRequired(
  value: LoginResponse | TwoFactorRequiredResponse,
): value is TwoFactorRequiredResponse {
  return (value as TwoFactorRequiredResponse).requiresTwoFactor === true;
}

export interface RefreshResponse {
  accessToken: string;
  refreshToken: string;
  expiresInSeconds: number;
}

export interface VaultItemResponse {
  id: string;
  type: VaultItemType;
  encryptedData: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
}

export interface SessionResponse {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

export interface AuditLogResponse {
  id: number;
  event: string;
  detail: string | null;
  ipAddress: string | null;
  createdAt: string;
}

export interface TwoFactorSetupResponse {
  secret: string;
  otpAuthUri: string;
}

export interface ProblemDetails {
  title?: string;
  detail?: string;
  status?: number;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}
