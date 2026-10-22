import { requestResponse } from './client';
import type {
  PortalAdminKey,
  PortalAdminStatus,
  PortalAdminUser,
  PortalInvite,
  PortalSyncReport,
  PortalUsageReport,
} from '../portal/types';

/**
 * The operator's customer-account endpoints (ADR 0105), on the console's own
 * facade so a 401 returns the operator to their sign-in and demo refusals are
 * reported the way every other page reports them.
 */
async function json<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await requestResponse(path, init);
  return (await response.json()) as T;
}

export interface PortalUserCreate {
  username: string;
  password: string;
  display_name?: string;
  note?: string;
  max_keys?: number;
}

export interface PortalUserPatch {
  display_name?: string;
  status?: 'active' | 'disabled';
  note?: string;
  max_keys?: number;
  password?: string;
}

export const portalAdminApi = {
  status: () => json<PortalAdminStatus>('/portal/status'),
  users: () => json<{ users: PortalAdminUser[] }>('/portal/users'),
  createUser: (payload: PortalUserCreate) =>
    json<{ user: PortalAdminUser }>('/portal/users', { method: 'POST', body: JSON.stringify(payload) }),
  updateUser: (id: number, patch: PortalUserPatch) =>
    json<{ user: PortalAdminUser }>(`/portal/users/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  userKeys: (id: number) => json<{ keys: PortalAdminKey[] }>(`/portal/users/${id}/keys`),
  userUsage: (id: number, days: number) => json<PortalUsageReport>(`/portal/users/${id}/usage?days=${days}`),
  revokeKey: (id: number) => json<unknown>(`/portal/keys/${id}`, { method: 'DELETE' }),
  invites: () => json<{ invites: PortalInvite[] }>('/portal/invites'),
  createInvite: (payload: { max_uses: number; expires_at_ms?: number; note?: string }) =>
    json<{ invite: PortalInvite; code: string }>('/portal/invites', { method: 'POST', body: JSON.stringify(payload) }),
  revokeInvite: (id: number) => json<unknown>(`/portal/invites/${id}`, { method: 'DELETE' }),
  sync: () => json<PortalSyncReport>('/portal/sync', { method: 'POST' }),
};
