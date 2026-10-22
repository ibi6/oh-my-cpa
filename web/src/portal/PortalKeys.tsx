import React from 'react';
import { Button, DatePicker, Form, Input, Modal, Table } from 'antd';
import type { Dayjs } from 'dayjs';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useT } from '../i18n';
import { PageHeader } from '../components/common/PageHeader';
import { Panel } from '../components/common/Panel';
import { PageLoading } from '../components/common/PageLoading';
import { EmptyState } from '../components/common/EmptyState';
import { ConfirmAction } from '../components/common/ConfirmAction';
import { CopyButton } from '../components/common/CopyButton';
import { Tag, type TagTone } from '../components/common/Tag';
import { LoadFailure, Notice, useToast } from '../components/feedback';
import { PlusOutlined } from '../components/icons';
import { portalApi } from './api';
import { portalErrorText } from './PortalAuth';
import { usePortal } from './PortalApp';
import { formatCount, formatDateTime } from './format';
import type { PortalKey, PortalKeyState } from './types';
import styles from './Portal.module.css';

export const KEY_STATE_TONES: Record<PortalKeyState, TagTone> = {
  active: 'success',
  pending: 'warn',
  missing: 'danger',
  expired: 'neutral',
  suspended: 'warn',
  revoked: 'neutral',
};

export const KeyStateTag: React.FC<{ state: PortalKeyState }> = ({ state }) => {
  const t = useT();
  return <Tag tone={KEY_STATE_TONES[state] ?? 'neutral'} size="small">{t(`portal.key_state.${state}`)}</Tag>;
};

export function keyMask(key: Pick<PortalKey, 'prefix' | 'last4'>): string {
  return `${key.prefix}…${key.last4}`;
}

export const PortalKeysPage: React.FC = () => {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { config } = usePortal();
  const keys = useQuery({ queryKey: ['portal', 'keys'], queryFn: portalApi.keys });
  const [isCreating, setIsCreating] = React.useState(false);
  const [issued, setIssued] = React.useState<string>();
  const [form] = Form.useForm<{ name: string; expires?: Dayjs }>();

  const create = useMutation({
    mutationFn: (values: { name: string; expires?: Dayjs }) =>
      portalApi.createKey(values.name, values.expires ? values.expires.endOf('day').valueOf() : undefined),
    onSuccess: (result) => {
      setIsCreating(false);
      form.resetFields();
      setIssued(result.secret);
      void queryClient.invalidateQueries({ queryKey: ['portal', 'keys'] });
    },
    onError: (err) => toast.error(t('portal.key_create_failed'), { detail: portalErrorText(t, err) }),
  });
  const revoke = useMutation({
    mutationFn: (id: number) => portalApi.revokeKey(id),
    onSuccess: () => {
      toast.success(t('portal.key_revoked'));
      void queryClient.invalidateQueries({ queryKey: ['portal', 'keys'] });
    },
    onError: (err) => toast.error(t('portal.key_revoke_failed'), { detail: portalErrorText(t, err) }),
  });

  const atLimit = keys.data !== undefined && keys.data.active_keys >= keys.data.max_keys;

  return (
    <>
      <PageHeader
        title={t('portal.keys_title')}
        subtitle={keys.data ? t('portal.keys_subtitle', { n: keys.data.active_keys, max: keys.data.max_keys }) : undefined}
        actions={(
          <Button type="primary" icon={<PlusOutlined />} disabled={atLimit} onClick={() => setIsCreating(true)}>
            {t('portal.key_create')}
          </Button>
        )}
      />
      {atLimit && <Notice tone="info" description={t('portal.key_limit_reached')} />}
      {keys.data?.keys.some((key) => key.state === 'missing') && (
        <Notice tone="warning" title={t('portal.key_missing_title')} description={t('portal.key_missing_body')} />
      )}
      <Panel>
        {keys.isPending ? <PageLoading variant="block" /> : keys.isError ? (
          <LoadFailure title={t('portal.keys_failed')} error={keys.error} onRetry={() => void keys.refetch()} />
        ) : (
          <Table<PortalKey>
            rowKey="id"
            dataSource={keys.data.keys}
            pagination={false}
            scroll={{ x: true }}
            locale={{ emptyText: <EmptyState size="compact" title={t('portal.no_keys')} description={t('portal.no_keys_hint')} /> }}
            columns={[
              { title: t('portal.col.name'), dataIndex: 'name' },
              { title: t('portal.col.key'), key: 'mask', render: (_, key) => <span className={styles['mono']}>{keyMask(key)}</span> },
              { title: t('portal.col.state'), dataIndex: 'state', render: (state: PortalKeyState) => <KeyStateTag state={state} /> },
              { title: t('portal.col.requests'), dataIndex: 'request_count', align: 'right', render: (v: number) => formatCount(v) },
              { title: t('portal.col.last_used'), dataIndex: 'last_used_at_ms', render: (v?: number) => formatDateTime(v) },
              { title: t('portal.col.expires'), dataIndex: 'expires_at_ms', render: (v?: number) => (v ? formatDateTime(v) : t('portal.never')) },
              { title: t('portal.col.created'), dataIndex: 'created_at_ms', render: (v: number) => formatDateTime(v) },
              {
                title: '',
                key: 'actions',
                align: 'right',
                render: (_, key) => key.status === 'active' ? (
                  <ConfirmAction
                    title={t('portal.key_revoke_confirm', { name: key.name })}
                    confirmLabel={t('portal.key_revoke')}
                    isDanger
                    isConfirming={revoke.isPending && revoke.variables === key.id}
                    onConfirm={() => revoke.mutateAsync(key.id).catch(() => undefined)}
                  >
                    <Button size="small" danger>{t('portal.key_revoke')}</Button>
                  </ConfirmAction>
                ) : null,
              },
            ]}
          />
        )}
      </Panel>

      <Modal
        open={isCreating}
        title={t('portal.key_create')}
        okText={t('portal.key_create')}
        confirmLoading={create.isPending}
        onOk={() => form.submit()}
        onCancel={() => setIsCreating(false)}
        destroyOnHidden
      >
        <Form form={form} layout="vertical" onFinish={(values) => create.mutate(values)} requiredMark={false}>
          <Form.Item name="name" label={t('portal.col.name')} rules={[{ required: true, message: t('portal.key_name_required') }, { max: 48 }]}>
            <Input autoFocus placeholder={t('portal.key_name_placeholder')} />
          </Form.Item>
          <Form.Item name="expires" label={t('portal.key_expires')} extra={t('portal.key_expires_hint')}>
            <DatePicker disabledDate={(day) => day.isBefore(new Date(), 'day')} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        open={issued !== undefined}
        title={t('portal.key_issued_title')}
        onCancel={() => setIssued(undefined)}
        footer={<Button type="primary" onClick={() => setIssued(undefined)}>{t('portal.key_issued_done')}</Button>}
        mask={{ closable: false }}
      >
        <Notice tone="warning" description={t('portal.key_issued_warning')} />
        <div className={styles['secret']}>
          <span>{issued}</span>
          {issued && <CopyButton text={issued} />}
        </div>
        {config.gateway_url && (
          <p className={styles['muted']}>{t('portal.key_issued_usage', { url: config.gateway_url })}</p>
        )}
      </Modal>
    </>
  );
};
