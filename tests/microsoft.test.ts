import { afterEach, describe, expect, it, vi } from 'vitest';
import AdminForthAdapterMicrosoftOauth2 from '../index.js';

function signInWithGraphUser(graphUser: Record<string, unknown>) {
  vi.stubGlobal('fetch', vi.fn()
    .mockResolvedValueOnce({ json: async () => ({ access_token: 'access-token' }) })
    .mockResolvedValueOnce({ json: async () => ({ id: 'oid-1', displayName: 'User', ...graphUser }) }));
  const adapter = new AdminForthAdapterMicrosoftOauth2({ clientID: 'client-id', clientSecret: 'client-secret' });
  return adapter.getTokenFromCode('code', 'https://admin.example.com/oauth/callback');
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('email of a Graph user', () => {
  it('is the UPN when mail is on another domain, as an admin of any tenant can set mail to anyone (nOAuth)', async () => {
    const userInfo = await signInWithGraphUser({ mail: 'admin@victim.com', userPrincipalName: 'attacker@attacker.onmicrosoft.com' });

    expect(userInfo.email).toBe('attacker@attacker.onmicrosoft.com');
  });

  it('is the mail when it is on the domain of the UPN, which the tenant had to verify', async () => {
    const userInfo = await signInWithGraphUser({ mail: 'John.Doe@Corp.com', userPrincipalName: 'jdoe@corp.com' });

    expect(userInfo.email).toBe('John.Doe@Corp.com');
  });
});
