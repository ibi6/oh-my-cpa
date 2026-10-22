import React from 'react';
import { Button, Form, Input } from 'antd';
import { useT } from '../i18n';
import { BrandArtwork } from '../components/common/BrandArtwork';
import { PreferenceMenus } from '../components/common/PreferenceMenus';
import { Notice } from '../components/feedback';
import { LockOutlined } from '../components/icons';
import { PortalApiError, portalApi } from './api';
import type { PortalPublicConfig, PortalSessionResponse } from './types';
import styles from './Portal.module.css';

/** The server's error codes, worded for a customer. */
export function portalErrorText(t: (key: string) => string, err: unknown): string {
  if (err instanceof PortalApiError) {
    const key = `portal.error.${err.code}`;
    const text = t(key);
    if (text !== key) return text;
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}

interface SignInProps {
  config: PortalPublicConfig;
  onSignedIn: (session: PortalSessionResponse) => void;
}

/**
 * Sign-in and, where the operator allows it, registration. It reuses the
 * console's sign-in column (`auth-shell`) so the two doors look alike, but it
 * talks only to /api/portal.
 */
export const PortalSignIn: React.FC<SignInProps> = ({ config, onSignedIn }) => {
  const t = useT();
  const [mode, setMode] = React.useState<'login' | 'register'>('login');
  const [error, setError] = React.useState<string>();
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const canRegister = config.registration === 'open' || config.registration === 'invite';

  const submit = async (values: { username: string; password: string; display_name?: string; invite_code?: string }) => {
    setIsSubmitting(true);
    setError(undefined);
    try {
      const result = mode === 'login'
        ? await portalApi.login(values.username, values.password)
        : await portalApi.register(values);
      onSignedIn(result);
    } catch (err) {
      setError(portalErrorText(t, err));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-shell">
      <header className="auth-header">
        <PreferenceMenus />
      </header>
      <main className="auth-main">
        <section className="auth-card" aria-labelledby="portal-auth-title">
          <div className="auth-brand">
            <BrandArtwork shape="wordmark" height={28} className="app-brand-logo" />
          </div>
          <h1 id="portal-auth-title" className="terminal-title auth-title">
            {mode === 'login' ? t('portal.login_title') : t('portal.register_title')}
          </h1>
          {error && <Notice tone="error" description={error} className="auth-alert" />}
          <Form key={mode} layout="vertical" onFinish={submit} requiredMark={false} size="large" className="auth-form">
            <Form.Item label={t('portal.username')} name="username" rules={[{ required: true, message: t('portal.username_required') }]}>
              <Input autoFocus autoComplete="username" spellCheck={false} />
            </Form.Item>
            {mode === 'register' && (
              <Form.Item label={t('portal.display_name')} name="display_name">
                <Input autoComplete="nickname" />
              </Form.Item>
            )}
            <Form.Item label={t('portal.password')} name="password" rules={[{ required: true, message: t('portal.password_required') }]}>
              <Input.Password
                prefix={<LockOutlined className="terminal-muted" />}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              />
            </Form.Item>
            {mode === 'register' && config.registration === 'invite' && (
              <Form.Item label={t('portal.invite_code')} name="invite_code" rules={[{ required: true, message: t('portal.invite_required') }]}>
                <Input spellCheck={false} autoComplete="off" />
              </Form.Item>
            )}
            <Button type="primary" htmlType="submit" block loading={isSubmitting} className="auth-submit">
              {mode === 'login' ? t('portal.sign_in') : t('portal.register')}
            </Button>
          </Form>
          {canRegister && (
            <div className={styles['switch-link']}>
              <Button type="link" onClick={() => { setError(undefined); setMode(mode === 'login' ? 'register' : 'login'); }}>
                {mode === 'login' ? t('portal.to_register') : t('portal.to_login')}
              </Button>
            </div>
          )}
        </section>
      </main>
    </div>
  );
};
