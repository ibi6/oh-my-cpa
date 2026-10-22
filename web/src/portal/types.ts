/**
 * Wire types of the customer portal (ADR 0105). They mirror the Go DTOs in
 * internal/api/portal_customer.go and portal_admin.go; a field the server does
 * not send is optional here.
 */

export type PortalRegistration = 'off' | 'invite' | 'open';

export interface PortalPublicConfig {
  enabled: boolean;
  registration?: PortalRegistration;
  gateway_url?: string;
  show_cost?: boolean;
}

export interface PortalUser {
  id: number;
  username: string;
  display_name: string;
  status: 'active' | 'disabled';
  max_keys: number;
  created_at_ms: number;
  last_login_at_ms?: number;
}

export interface PortalSessionResponse {
  authenticated: boolean;
  user?: PortalUser;
}

/** `state` is the one word a key's row leads with: whether it works now. */
export type PortalKeyState = 'active' | 'pending' | 'missing' | 'expired' | 'suspended' | 'revoked';

export interface PortalKey {
  id: number;
  name: string;
  prefix: string;
  last4: string;
  status: 'active' | 'revoked';
  state: PortalKeyState;
  sync_state: string;
  expires_at_ms?: number;
  request_count: number;
  last_used_at_ms?: number;
  created_at_ms: number;
  revoked_at_ms?: number;
}

export interface PortalKeysResponse {
  keys: PortalKey[];
  max_keys: number;
  active_keys: number;
}

export interface PortalCreatedKey {
  key: PortalKey;
  /** The plaintext, present in this one response only. */
  secret: string;
}

export interface PortalUsageMeasures {
  requests: number;
  failed_requests: number;
  input_tokens: number;
  output_tokens: number;
  reasoning_tokens: number;
  cached_tokens: number;
  total_tokens: number;
  cost_usd?: number;
}

export interface PortalUsageGroup extends PortalUsageMeasures {
  day_start_ms?: number;
  model?: string;
  key_id?: number;
  key_name?: string;
}

export interface PortalUsageReport {
  window: { from_day_ms: number; to_day_ms: number; days: number; timezone: string };
  lifetime: PortalUsageMeasures;
  last_24h: PortalUsageMeasures;
  totals: PortalUsageMeasures;
  daily: PortalUsageGroup[];
  models: PortalUsageGroup[];
  keys: PortalUsageGroup[];
}

export interface PortalUsageEvent {
  id: number;
  timestamp_ms: number;
  key_id?: number;
  key_name?: string;
  model: string;
  failed: boolean;
  status_code?: number;
  stream?: boolean;
  latency_ms: number;
  ttft_ms?: number;
  input_tokens: number;
  output_tokens: number;
  reasoning_tokens: number;
  cached_tokens: number;
  total_tokens: number;
  cost_usd?: number;
  request_id?: string;
}

export interface PortalUsageEventPage {
  items: PortalUsageEvent[];
  next_cursor?: string;
  has_more: boolean;
  limit: number;
}

/** The operator's view of an account. */
export interface PortalAdminUser extends PortalUser {
  origin: 'admin' | 'invite' | 'open';
  note: string;
  updated_at_ms: number;
  active_keys: number;
  total_keys: number;
  requests: number;
  total_tokens: number;
  cost_usd?: number;
  last_used_at_ms?: number;
}

export interface PortalAdminKey extends PortalKey {
  user_id: number;
  sync_error?: string;
  synced_at_ms?: number;
}

export interface PortalInvite {
  id: number;
  code_prefix: string;
  note: string;
  max_uses: number;
  used_count: number;
  expires_at_ms?: number;
  revoked_at_ms?: number;
  created_at_ms: number;
}

export interface PortalAdminStatus {
  enabled: boolean;
  registration: PortalRegistration;
  gateway_url: string;
  show_cost: boolean;
  session_ttl_s: number;
  sync_s: number;
  portal_path: string;
  users?: number;
}

export interface PortalSyncReport {
  checked: number;
  synced: number;
  removed: number;
  missing: number;
  failed: number;
}
