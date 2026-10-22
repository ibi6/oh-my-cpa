/** Number and time formatting for the customer portal, in the reader's locale. */

export function formatCount(value: number | undefined): string {
  return new Intl.NumberFormat().format(value ?? 0);
}

export function formatTokens(value: number | undefined): string {
  const n = value ?? 0;
  if (Math.abs(n) < 10_000) return formatCount(n);
  return new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 2 }).format(n);
}

export function formatUSD(value: number | undefined): string {
  if (value === undefined || !Number.isFinite(value)) return '—';
  return `$${value.toFixed(value !== 0 && Math.abs(value) < 0.01 ? 4 : 2)}`;
}

export function formatDateTime(ms: number | undefined): string {
  if (!ms) return '—';
  return new Date(ms).toLocaleString();
}

/** A UTC day start, shown as the UTC date it names. */
export function formatUTCDay(ms: number | undefined): string {
  if (ms === undefined) return '—';
  return new Date(ms).toISOString().slice(0, 10);
}
