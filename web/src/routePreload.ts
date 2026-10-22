import {
  loadUsageEventsPage,
  loadPricingPage,
  loadProvidersPage,
  loadApiKeysPage,
  loadDashboardPage,
  loadAgentPage,
  loadPlaygroundPage,
  loadModelSquarePage,
  loadLogsPage,
  loadAuditPage,
  loadConfigPage,
  loadOAuthManagementPage,
  loadLegacyOAuthManagementRedirect,
  loadSystemPage,
  loadPluginsPage,
  loadPluginPageHost,
  loadOmcSettingsPage,
  loadPortalUsersPage,
} from './routePages';

const ROUTE_LOADERS: Record<string, () => Promise<unknown>> = {
  '/usage/events': loadUsageEventsPage,
  '/pricing': loadPricingPage,
  '/ai-providers': loadProvidersPage,
  '/api-keys': loadApiKeysPage,
  '/dashboard': loadDashboardPage,
  '/agent': loadAgentPage,
  '/playground': loadPlaygroundPage,
  '/model-square': loadModelSquarePage,
  '/logs': loadLogsPage,
  '/audit': loadAuditPage,
  '/config': loadConfigPage,
  '/oauth-management': loadOAuthManagementPage,
  '/auth-files': loadLegacyOAuthManagementRedirect,
  '/system': loadSystemPage,
  '/plugins': loadPluginsPage,
  '/plugins/store': loadPluginsPage,
  '/omc-settings': loadOmcSettingsPage,
  '/portal-users': loadPortalUsersPage,
};

export function preloadRoute(path: string): void {
  // Code only: intent must not send authenticated reads or mount a page's effects.
  // A plugin's page has a route per plugin, all served by one module.
  const loadRoute = path.startsWith('/plugin-pages/') ? loadPluginPageHost : ROUTE_LOADERS[path];
  if (loadRoute) void loadRoute().catch(() => undefined);
}
