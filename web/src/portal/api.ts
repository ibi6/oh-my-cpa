import { getAppConfig } from '../types/config';
import type {
  PortalCreatedKey,
  PortalKeysResponse,
  PortalPublicConfig,
  PortalSessionResponse,
  PortalUsageEventPage,
  PortalUsageReport,
} from './types';

/**
 * The customer portal's own HTTP client.
 *
 * It is deliberately not the console's `api` facade: that one sends a 401 to the
 * operator's sign-in screen and reports demo writes, and neither applies to a
 * customer. A portal 401 means "your portal session ended" and is handled by
 * the portal shell alone.
 */
export class PortalApiError extends Error {
  status: number;
  code: string;

  constructor(message: string, status: number, code: string) {
    super(message);
    this.name = 'PortalApiError';
    this.status = status;
    this.code = code;
  }
}

export function portalApiRoot(): string {
  const { basePath } = getAppConfig();
  return `${basePath}/api/portal`;
}

type UnauthorizedListener = () => void;
let unauthorizedListener: UnauthorizedListener | undefined;

export function onPortalUnauthorized(listener: UnauthorizedListener | undefined): void {
  unauthorizedListener = listener;
}

async function portalRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json', ...(init.headers as Record<string, string> | undefined) };
  if (typeof init.body === 'string') headers['Content-Type'] = 'application/json';
  let response: Response;
  try {
    response = await fetch(`${portalApiRoot()}${path}`, { ...init, headers, credentials: 'same-origin' });
  } catch (err: unknown) {
    throw new PortalApiError(err instanceof Error ? err.message : String(err), 0, 'network');
  }
  if (!response.ok) {
    let code = '';
    let message = `HTTP ${response.status}`;
    try {
      const body = (await response.json()) as { code?: unknown; error?: unknown };
      if (typeof body.code === 'string') code = body.code;
      if (typeof body.error === 'string') message = body.error;
    } catch {
      // A body that is not JSON keeps the status as its message.
    }
    if (response.status === 401 && path !== '/auth/login') unauthorizedListener?.();
    throw new PortalApiError(message, response.status, code);
  }
  return (await response.json()) as T;
}

export const portalApi = {
  config: () => portalRequest<PortalPublicConfig>('/config'),
  session: () => portalRequest<PortalSessionResponse>('/auth/session'),
  login: (username: string, password: string) =>
    portalRequest<PortalSessionResponse>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  register: (payload: { username: string; password: string; display_name?: string; invite_code?: string }) =>
    portalRequest<PortalSessionResponse>('/auth/register', { method: 'POST', body: JSON.stringify(payload) }),
  logout: () => portalRequest<PortalSessionResponse>('/auth/logout', { method: 'POST' }),
  changePassword: (currentPassword: string, newPassword: string) =>
    portalRequest<{ status: string }>('/me/password', {
      method: 'PUT',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
  keys: () => portalRequest<PortalKeysResponse>('/keys'),
  createKey: (name: string, expiresAtMS?: number) =>
    portalRequest<PortalCreatedKey>('/keys', { method: 'POST', body: JSON.stringify({ name, expires_at_ms: expiresAtMS }) }),
  revokeKey: (id: number) => portalRequest<unknown>(`/keys/${id}`, { method: 'DELETE' }),
  usage: (days: number) => portalRequest<PortalUsageReport>(`/usage/overview?days=${days}`),
  events: (params: { cursor?: string; keyId?: number; result?: string; limit?: number }) => {
    const search = new URLSearchParams();
    if (params.cursor) search.set('cursor', params.cursor);
    if (params.keyId) search.set('key_id', String(params.keyId));
    if (params.result && params.result !== 'all') search.set('result', params.result);
    if (params.limit) search.set('limit', String(params.limit));
    const query = search.toString();
    return portalRequest<PortalUsageEventPage>(`/usage/events${query ? `?${query}` : ''}`);
  },
};
