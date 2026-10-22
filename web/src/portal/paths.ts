import { getAppConfig } from '../types/config';

/** The address under which the portal is served: the console's base path plus /portal. */
export function portalBasePath(): string {
  return `${getAppConfig().basePath}/portal`;
}

/**
 * Whether a browser path is the customer portal rather than the operator console.
 * Kept apart from the portal's components so the console's entry can decide
 * which application to mount without downloading the portal.
 */
export function isPortalPath(pathname: string): boolean {
  const base = portalBasePath();
  return pathname === base || pathname.startsWith(`${base}/`);
}
