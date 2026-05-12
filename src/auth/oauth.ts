import type { OAuthTokens } from './types';
import { CLIError } from '../errors/base';
import { ExitCode } from '../errors/codes';

// OAuth configuration
export interface OAuthConfig {
  clientId: string;
  clientName: string;
  tokenUrl: string;
  deviceCodeUrl: string;
  scopes: string[];
}

export async function startDeviceCodeFlow(
  config: OAuthConfig,
): Promise<OAuthTokens> {
  const { randomBytes, createHash } = await import('crypto');
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  const state = randomBytes(16).toString('base64url');

  const lane = process.env.BEDROCK_LANE;
  const extraHeaders: Record<string, string> = lane ? { bedrock_lane: lane } : {};
  if (process.env.X_USER_PRE) extraHeaders['X-User-Pre'] = 'true';

  // Request device code with PKCE
  const codeRes = await fetch(config.deviceCodeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...extraHeaders },
    body: new URLSearchParams({
      client_id: config.clientId,
      scope: config.scopes.join(' '),
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    }),
  });

  if (!codeRes.ok) {
    const body = await codeRes.text().catch(() => '');
    throw new CLIError(
      `Failed to start device code flow: HTTP ${codeRes.status} ${body}`,
      ExitCode.AUTH,
      `URL: ${config.deviceCodeUrl}`,
    );
  }

  const data = (await codeRes.json()) as {
    user_code: string;
    verification_uri: string;
    expired_in: number; // Unix timestamp (ms)
    interval: number;   // milliseconds
    state: string;
  };

  if (data.state !== state) {
    throw new CLIError('OAuth state mismatch: possible CSRF attack.', ExitCode.AUTH);
  }

  const url = data.verification_uri;

  const { exec } = await import('child_process');
  const openCmd = process.platform === 'darwin' ? 'open' :
    process.platform === 'win32' ? 'start' : 'xdg-open';
  exec(`${openCmd} "${url}"`);

  process.stderr.write(`\nOpened: ${url}\n`);
  process.stderr.write(`Enter code: ${data.user_code}\n`);
  process.stderr.write('Waiting for authorization...\n');

  // Poll for authorization (expired_in is Unix timestamp in ms)
  const deadline = data.expired_in;
  const pollInterval = data.interval || 5000;

  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, pollInterval));

    const tokenRes = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...extraHeaders },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: config.clientId,
        user_code: data.user_code,
        code_verifier: codeVerifier,
      }),
    });

    if (!tokenRes.ok) {
      throw new CLIError(
        `Device code authorization failed: HTTP ${tokenRes.status}`,
        ExitCode.AUTH,
      );
    }

    const tokenData = (await tokenRes.json()) as {
      status: string;
      access_token?: string;
      refresh_token?: string;
      expired_in?: number;
      resource_url?: string;
    };

    if (tokenData.status === 'success' && tokenData.access_token) {
      return {
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token ?? '',
        expired_in: tokenData.expired_in ?? 0,
        token_type: 'Bearer',
        resource_url: tokenData.resource_url,
      };
    }

    if (tokenData.status === 'pending') continue;

    throw new CLIError(
      `Device code authorization failed: ${tokenData.status}`,
      ExitCode.AUTH,
    );
  }

  throw new CLIError('Device code authorization timed out.', ExitCode.TIMEOUT);
}
