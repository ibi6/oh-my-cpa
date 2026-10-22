import React from 'react';
import { Button, Form, Input } from 'antd';
import { useMutation } from '@tanstack/react-query';
import { useT } from '../i18n';
import { PageHeader } from '../components/common/PageHeader';
import { Panel } from '../components/common/Panel';
import { useToast } from '../components/feedback';
import { portalApi } from './api';
import { portalErrorText } from './PortalAuth';
import { usePortal } from './PortalApp';
import { formatDateTime } from './format';
import styles from './Portal.module.css';

export const PortalAccountPage: React.FC = () => {
  const t = useT();
  const toast = useToast();
  const { user } = usePortal();
  const [form] = Form.useForm<{ current: string; next: string; confirm: string }>();
  const change = useMutation({
    mutationFn: (values: { current: string; next: string }) => portalApi.changePassword(values.current, values.next),
    onSuccess: () => {
      form.resetFields();
      toast.success(t('portal.password_changed'));
    },
    onError: (err) => toast.error(t('portal.password_change_failed'), { detail: portalErrorText(t, err) }),
  });
  return (
    <>
      <PageHeader title={t('portal.account_title')} subtitle={user.username} />
      <Panel title={t('portal.account_profile')}>
        <p>{t('portal.username')}: <span className={styles['mono']}>{user.username}</span></p>
        {user.display_name && <p>{t('portal.display_name')}: {user.display_name}</p>}
        <p className={styles['muted']}>{t('portal.account_created', { at: formatDateTime(user.created_at_ms) })}</p>
      </Panel>
      <Panel title={t('portal.change_password')}>
        <Form form={form} layout="vertical" requiredMark={false} onFinish={(values) => change.mutate(values)} style={{ maxWidth: 420 }}>
          <Form.Item name="current" label={t('portal.current_password')} rules={[{ required: true, message: t('portal.password_required') }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item name="next" label={t('portal.new_password')} rules={[{ required: true, min: 8, message: t('portal.password_rule') }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm"
            label={t('portal.confirm_password')}
            dependencies={['next']}
            rules={[
              { required: true, message: t('portal.password_required') },
              ({ getFieldValue }) => ({
                validator: (_, value) => (value === getFieldValue('next') ? Promise.resolve() : Promise.reject(new Error(t('portal.password_mismatch')))),
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={change.isPending}>{t('portal.change_password')}</Button>
        </Form>
      </Panel>
    </>
  );
};
