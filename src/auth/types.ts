export type AuthMethod = 'api-key' | 'oauth';

export interface OAuthTokens {
  access_token: string;
  refresh_token: string;
  expired_in: number; // milliseconds
  token_type: 'Bearer';
  resource_url?: string;
}

export interface CredentialFile {
  access_token: string;
  refresh_token: string;
  expires_at: string; // ISO 8601
  token_type: 'Bearer';
  resource_url?: string;
  account?: string;
}

export interface ResolvedCredential {
  token: string;
  method: AuthMethod;
  source: string;
}
