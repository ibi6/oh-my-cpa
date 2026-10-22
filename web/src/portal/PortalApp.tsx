import React from 'react';
import { createBrowserRouter, Navigate, NavLink, Outlet, RouterProvider, useLocation } from 'react-router-dom';
import { Button, Menu } from 'antd';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { portalBasePath } from './paths';
import { useT } from '../i18n';
import { BrandArtwork } from '../components/common/BrandArtwork';
import { PreferenceMenus } from '../components/common/PreferenceMenus';
import { PageLoading } from '../components/common/PageLoading';
import { LoadFailure } from '../components/feedback';
import { LogoutOutlined } from '../components/icons';
import { onPortalUnauthorized, portalApi } from './api';
import type { PortalPublicConfig, PortalUser } from './types';
import { PortalSignIn } from './PortalAuth';
import { PortalOverviewPage } from './PortalOverview';
import { PortalKeysPage } from './PortalKeys';
import { PortalUsagePage } from './PortalUsage';
import { PortalAccountPage } from './PortalAccount';
import styles from './Portal.module.css';

/** What every portal page reads: the signed-in customer and the portal's public settings. */
export interface PortalContextValue {
  user: PortalUser;
  config: PortalPublicConfig;
  signOut: () => Promise<void>;
}

export const PortalContext = React.createContext<PortalContextValue | null>(null);

export function usePortal(): PortalContextValue {
  const value = React.useContext(PortalContext);
  if (!value) throw new Error('usePortal outside the portal shell');
  return value;
}

/**
 * The customer portal (ADR 0105): a separate application under <base>/portal
 * with its own session. It never mounts the operator console's AuthGate or
 * shell, so nothing in it can read an operator endpoint.
 */
export const PortalApp: React.FC = () => {
  const t = useT();
  const queryClient = useQueryClient();
  const config = useQuery({ queryKey: ['portal', 'config'], queryFn: portalApi.config, staleTime: 60_000 });
  const session = useQuery({
    queryKey: ['portal', 'session'],
    queryFn: portalApi.session,
    enabled: config.data?.enabled === true,
    retry: false,
  });

  React.useEffect(() => {
    onPortalUnauthorized(() => {
      queryClient.setQueryData(['portal', 'session'], { authenticated: false });
    });
    return () => onPortalUnauthorized(undefined);
  }, [queryClient]);

  const signOut = React.useCallback(async () => {
    try {
      await portalApi.logout();
    } finally {
      queryClient.removeQueries({ queryKey: ['portal'], exact: false });
      queryClient.setQueryData(['portal', 'session'], { authenticated: false });
      await config.refetch();
    }
  }, [queryClient, config]);

  if (config.isPending) return <PageLoading />;
  if (config.isError) {
    return (
      <main className={styles['main']}>
        <LoadFailure title={t('portal.load_failed')} error={config.error} onRetry={() => void config.refetch()} />
      </main>
    );
  }
  if (!config.data.enabled) {
    return (
      <div className="auth-shell">
        <main className="auth-main">
          <section className="auth-card">
            <div className="auth-brand"><BrandArtwork shape="wordmark" height={28} className="app-brand-logo" /></div>
            <h1 className="terminal-title auth-title">{t('portal.disabled_title')}</h1>
            <p className="terminal-muted">{t('portal.disabled_body')}</p>
          </section>
        </main>
      </div>
    );
  }
  if (session.isPending) return <PageLoading />;
  if (session.isError) {
    return (
      <main className={styles['main']}>
        <LoadFailure title={t('portal.load_failed')} error={session.error} onRetry={() => void session.refetch()} />
      </main>
    );
  }
  if (!session.data.authenticated || !session.data.user) {
    return (
      <PortalSignIn
        config={config.data}
        onSignedIn={(result) => {
          queryClient.setQueryData(['portal', 'session'], result);
        }}
      />
    );
  }
  return (
    <PortalContext.Provider value={{ user: session.data.user, config: config.data, signOut }}>
      <PortalRouter />
    </PortalContext.Provider>
  );
};

const PortalRouter: React.FC = () => {
  const router = React.useMemo(() => createBrowserRouter(
    [{
      path: '/',
      element: <PortalShell />,
      children: [
        { index: true, element: <PortalOverviewPage /> },
        { path: 'keys', element: <PortalKeysPage /> },
        { path: 'usage', element: <PortalUsagePage /> },
        { path: 'account', element: <PortalAccountPage /> },
        { path: '*', element: <Navigate to="/" replace /> },
      ],
    }],
    { basename: portalBasePath() },
  ), []);
  return <RouterProvider router={router} />;
};

const NAV = [
  { path: '/', labelKey: 'portal.nav.overview' },
  { path: '/keys', labelKey: 'portal.nav.keys' },
  { path: '/usage', labelKey: 'portal.nav.usage' },
  { path: '/account', labelKey: 'portal.nav.account' },
];

const PortalShell: React.FC = () => {
  const t = useT();
  const { user, signOut } = usePortal();
  const location = useLocation();
  const selected = NAV.find((item) => item.path !== '/' && location.pathname.startsWith(item.path))?.path ?? '/';
  return (
    <div className={styles['shell']}>
      <header className={styles['header']}>
        <div className={styles['brand']}>
          <BrandArtwork shape="wordmark" height={22} className="app-brand-logo" />
          <span className={styles['muted']}>{t('portal.brand_suffix')}</span>
        </div>
        <Menu
          mode="horizontal"
          className={styles['nav']}
          selectedKeys={[selected]}
          items={NAV.map((item) => ({ key: item.path, label: <NavLink to={item.path}>{t(item.labelKey)}</NavLink> }))}
        />
        <div className={styles['user']}>
          <PreferenceMenus />
          <span>{user.display_name || user.username}</span>
          <Button size="small" icon={<LogoutOutlined />} onClick={() => void signOut()}>
            {t('portal.sign_out')}
          </Button>
        </div>
      </header>
      <main className={styles['main']}>
        <Outlet />
      </main>
    </div>
  );
};
