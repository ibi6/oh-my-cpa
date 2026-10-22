import React from 'react';
import { Button, DatePicker, Form, Input, InputNumber, Modal, Space, Table } from 'antd';
import type { Dayjs } from 'dayjs';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { useT } from '../../i18n';
import { portalAdminApi, type PortalUserPatch } from '../../api/portalAdmin';
import { PageHeader } from '../../components/common/PageHeader';
import { Panel } from '../../components/common/Panel';
import { PageLoading } from '../../components/common/PageLoading';
import { EmptyState } from '../../components/common/EmptyState';
import { ConfirmAction } from '../../components/common/ConfirmAction';
import { CopyButton } from '../../components/common/CopyButton';
import { AppDrawer } from '../../components/common/AppDrawer';
import { Tag } from '../../components/common/Tag';
import { LoadFailure, Notice, useToast } from '../../components/feedback';
import { PlusOutlined, SyncOutlined } from '../../components/icons';
import { KeyStateTag, keyMask } from '../../portal/PortalKeys';
import { UsageBreakdowns, UsageSummary } from '../../portal/PortalOverview';
import { formatCount, formatDateTime, formatTokens, formatUSD } from '../../portal/format';
import type { PortalAdminKey, PortalAdminUser, PortalInvite } from '../../portal/types';
import { isDemoMode } from '../../types/demoMode';
import styles from '../../portal/Portal.module.css';

const PORTAL_QUERY = ['portal-admin'] as const;

interface CreateValues {
  username: string;
  password: string;
  display_name?: string;
  note?: string;
  max_keys?: number;
}

interface EditValues {
  display_name?: string;
  note?: string;
  max_keys?: number;
  password?: string;
}

/**
 * The operator's customer accounts (ADR 0105): create and disable accounts,
 * see and revoke their keys, issue invites, and reconcile keys with CPA.
 */
export const PortalUsersPage: React.FC = () => {
  const t = useT();
  // The demonstration refuses every portal route, so the page says so rather than reading.
  if (isDemoMode()) {
    return (
      <>
        <PageHeader title={t('nav.portal_users')} subtitle={t('portal_admin.subtitle')} />
        <Notice tone="info" title={t('portal_admin.demo')} data-testid="portal-users-demo" />
      </>
    );
  }
  return <PortalUsersConsole />;
};

const PortalUsersConsole: React.FC = () => {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const status = useQuery({ queryKey: [...PORTAL_QUERY, 'status'], queryFn: portalAdminApi.status });
  const users = useQuery({ queryKey: [...PORTAL_QUERY, 'users'], queryFn: portalAdminApi.users });
  const enabled = status.data?.enabled === true;
  const invites = useQuery({ queryKey: [...PORTAL_QUERY, 'invites'], queryFn: portalAdminApi.invites, enabled });
  const [isCreating, setIsCreating] = React.useState(false);
  const [editing, setEditing] = React.useState<PortalAdminUser>();
  const [inspecting, setInspecting] = React.useState<PortalAdminUser>();
  const [isInviting, setIsInviting] = React.useState(false);
  const [inviteCode, setInviteCode] = React.useState<string>();
  const [createForm] = Form.useForm<CreateValues>();
  const [editForm] = Form.useForm<EditValues>();
  const [inviteForm] = Form.useForm<{ max_uses: number; expires?: Dayjs; note?: string }>();

  const refresh = () => void queryClient.invalidateQueries({ queryKey: PORTAL_QUERY });

  const createUser = useMutation({
    mutationFn: (values: CreateValues) => portalAdminApi.createUser(values),
    onSuccess: ({ user }) => {
      setIsCreating(false);
      createForm.resetFields();
      toast.success(t('portal_admin.user_created', { name: user.username }));
      refresh();
    },
    onError: (err) => toast.error(t('portal_admin.user_create_failed'), { error: err }),
  });
  const updateUser = useMutation({
    mutationFn: ({ id, patch }: { id: number; patch: PortalUserPatch }) => portalAdminApi.updateUser(id, patch),
    onSuccess: () => {
      setEditing(undefined);
      toast.success(t('portal_admin.user_updated'));
      refresh();
    },
    onError: (err) => toast.error(t('portal_admin.user_update_failed'), { error: err }),
  });
  const sync = useMutation({
    mutationFn: portalAdminApi.sync,
    onSuccess: (report) => {
      toast.success(t('portal_admin.sync_done', { checked: report.checked, missing: report.missing, removed: report.removed, failed: report.failed }));
      refresh();
    },
    onError: (err) => toast.error(t('portal_admin.sync_failed'), { error: err }),
  });
  const createInvite = useMutation({
    mutationFn: (values: { max_uses: number; expires?: Dayjs; note?: string }) => portalAdminApi.createInvite({
      max_uses: values.max_uses,
      note: values.note,
      expires_at_ms: values.expires ? values.expires.endOf('day').valueOf() : undefined,
    }),
    onSuccess: ({ code }) => {
      setIsInviting(false);
      inviteForm.resetFields();
      setInviteCode(code);
      refresh();
    },
    onError: (err) => toast.error(t('portal_admin.invite_create_failed'), { error: err }),
  });
  const revokeInvite = useMutation({
    mutationFn: (id: number) => portalAdminApi.revokeInvite(id),
    onSuccess: () => refresh(),
    onError: (err) => toast.error(t('portal_admin.invite_revoke_failed'), { error: err }),
  });

  const portalURL = status.data ? `${window.location.origin}${status.data.portal_path}` : '';

  const userColumns = [
    {
      title: t('portal.username'),
      dataIndex: 'username',
      render: (value: string, user: PortalAdminUser) => (
        <Space orientation="vertical" size={0}>
          <Button type="link" size="small" onClick={() => setInspecting(user)}>{value}</Button>
          {user.display_name && <span className={styles['muted']}>{user.display_name}</span>}
        </Space>
      ),
    },
    {
      title: t('portal.col.state'),
      dataIndex: 'status',
      render: (value: string) => <Tag size="small" tone={value === 'active' ? 'success' : 'warn'}>{t(`portal_admin.status.${value}`)}</Tag>,
    },
    { title: t('portal_admin.col.origin'), dataIndex: 'origin', render: (value: string) => t(`portal_admin.origin.${value}`) },
    { title: t('portal_admin.col.keys'), key: 'keys', render: (_: unknown, user: PortalAdminUser) => `${user.active_keys} / ${user.max_keys}` },
    { title: t('portal.col.requests'), dataIndex: 'requests', align: 'right' as const, render: (v: number) => formatCount(v) },
    { title: t('portal.col.tokens'), dataIndex: 'total_tokens', align: 'right' as const, render: (v: number) => formatTokens(v) },
    { title: t('portal.col.cost'), dataIndex: 'cost_usd', align: 'right' as const, render: (v?: number) => formatUSD(v) },
    { title: t('portal.col.last_used'), dataIndex: 'last_used_at_ms', render: (v?: number) => formatDateTime(v) },
    {
      title: '',
      key: 'actions',
      align: 'right' as const,
      render: (_: unknown, user: PortalAdminUser) => (
        <Space size={4}>
          <Button size="small" disabled={!enabled} onClick={() => {
            editForm.setFieldsValue({ display_name: user.display_name, note: user.note, max_keys: user.max_keys, password: undefined });
            setEditing(user);
          }}>{t('portal_admin.edit')}</Button>
          <ConfirmAction
            title={user.status === 'active' ? t('portal_admin.disable_confirm', { name: user.username }) : t('portal_admin.enable_confirm', { name: user.username })}
            confirmLabel={user.status === 'active' ? t('portal_admin.disable') : t('portal_admin.enable')}
            isDanger={user.status === 'active'}
            onConfirm={() => updateUser.mutateAsync({ id: user.id, patch: { status: user.status === 'active' ? 'disabled' : 'active' } }).catch(() => undefined)}
          >
            <Button size="small" danger={user.status === 'active'} disabled={!enabled}>
              {user.status === 'active' ? t('portal_admin.disable') : t('portal_admin.enable')}
            </Button>
          </ConfirmAction>
        </Space>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title={t('nav.portal_users')}
        subtitle={t('portal_admin.subtitle')}
        actions={(
          <>
            <Button icon={<SyncOutlined />} disabled={!enabled} loading={sync.isPending} onClick={() => sync.mutate()}>
              {t('portal_admin.sync')}
            </Button>
            <Button type="primary" icon={<PlusOutlined />} disabled={!enabled} onClick={() => setIsCreating(true)}>
              {t('portal_admin.create_user')}
            </Button>
          </>
        )}
      />
      {status.isError ? (
        <LoadFailure title={t('portal_admin.status_failed')} error={status.error} onRetry={() => void status.refetch()} />
      ) : status.data && !enabled ? (
        <Notice tone="info" title={t('portal_admin.disabled_title')} description={t('portal_admin.disabled_body')} />
      ) : status.data ? (
        <Panel>
          <Space orientation="vertical" size={4}>
            <span>
              {t('portal_admin.portal_url')}: <a href={portalURL} target="_blank" rel="noreferrer">{portalURL}</a> <CopyButton text={portalURL} />
            </span>
            <span className={styles['muted']}>
              {t('portal_admin.status_line', {
                registration: t(`portal_admin.registration.${status.data.registration}`),
                cost: status.data.show_cost ? t('portal_admin.cost_shown') : t('portal_admin.cost_hidden'),
                sync: status.data.sync_s,
              })}
            </span>
            {!status.data.gateway_url && <span className={styles['muted']}>{t('portal_admin.no_gateway_url')}</span>}
          </Space>
        </Panel>
      ) : null}

      <Panel title={t('portal_admin.users_title')}>
        {users.isPending ? <PageLoading variant="block" /> : users.isError ? (
          <LoadFailure title={t('portal_admin.users_failed')} error={users.error} onRetry={() => void users.refetch()} />
        ) : (
          <Table<PortalAdminUser>
            rowKey="id"
            dataSource={users.data.users}
            columns={userColumns}
            pagination={false}
            scroll={{ x: true }}
            locale={{ emptyText: <EmptyState size="compact" title={t('portal_admin.no_users')} description={enabled ? t('portal_admin.no_users_hint') : undefined} /> }}
          />
        )}
      </Panel>

      {enabled && (
        <Panel
          title={t('portal_admin.invites_title')}
          extra={<Button size="small" icon={<PlusOutlined />} onClick={() => setIsInviting(true)}>{t('portal_admin.invite_create')}</Button>}
        >
          {status.data?.registration !== 'invite' && <p className={styles['muted']}>{t('portal_admin.invites_inactive')}</p>}
          {invites.isError ? (
            <LoadFailure title={t('portal_admin.invites_failed')} error={invites.error} onRetry={() => void invites.refetch()} />
          ) : (
            <Table<PortalInvite>
              rowKey="id"
              size="small"
              loading={invites.isPending}
              dataSource={invites.data?.invites ?? []}
              pagination={false}
              locale={{ emptyText: <EmptyState size="compact" title={t('portal_admin.no_invites')} /> }}
              columns={[
                { title: t('portal_admin.col.code'), dataIndex: 'code_prefix', render: (v: string) => <span className={styles['mono']}>{v}…</span> },
                { title: t('portal_admin.col.uses'), key: 'uses', render: (_, invite) => `${invite.used_count} / ${invite.max_uses}` },
                { title: t('portal.col.expires'), dataIndex: 'expires_at_ms', render: (v?: number) => (v ? formatDateTime(v) : t('portal.never')) },
                { title: t('portal_admin.col.note'), dataIndex: 'note' },
                {
                  title: '',
                  key: 'actions',
                  align: 'right',
                  render: (_, invite) => invite.revoked_at_ms ? <Tag size="small">{t('portal_admin.invite_revoked')}</Tag> : (
                    <ConfirmAction title={t('portal_admin.invite_revoke_confirm')} confirmLabel={t('portal_admin.invite_revoke')} isDanger
                      onConfirm={() => revokeInvite.mutateAsync(invite.id).catch(() => undefined)}>
                      <Button size="small" danger>{t('portal_admin.invite_revoke')}</Button>
                    </ConfirmAction>
                  ),
                },
              ]}
            />
          )}
        </Panel>
      )}

      <Modal open={isCreating} title={t('portal_admin.create_user')} okText={t('portal_admin.create_user')}
        confirmLoading={createUser.isPending} onOk={() => createForm.submit()} onCancel={() => setIsCreating(false)} destroyOnHidden>
        <Form form={createForm} layout="vertical" requiredMark={false} onFinish={(values) => createUser.mutate(values)} initialValues={{ max_keys: 10 }}>
          <Form.Item name="username" label={t('portal.username')} extra={t('portal_admin.username_rule')} rules={[{ required: true, message: t('portal.username_required') }]}>
            <Input autoFocus autoComplete="off" spellCheck={false} />
          </Form.Item>
          <Form.Item name="password" label={t('portal.password')} extra={t('portal.password_rule')} rules={[{ required: true, min: 8, message: t('portal.password_rule') }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="display_name" label={t('portal.display_name')}><Input /></Form.Item>
          <Form.Item name="max_keys" label={t('portal_admin.max_keys')}><InputNumber min={0} max={1000} /></Form.Item>
          <Form.Item name="note" label={t('portal_admin.col.note')}><Input.TextArea rows={2} maxLength={500} /></Form.Item>
        </Form>
      </Modal>

      <Modal open={editing !== undefined} title={t('portal_admin.edit_title', { name: editing?.username ?? '' })} okText={t('common.save')}
        confirmLoading={updateUser.isPending} onOk={() => editForm.submit()} onCancel={() => setEditing(undefined)} destroyOnHidden>
        <Form form={editForm} layout="vertical" requiredMark={false} onFinish={(values) => {
          if (!editing) return;
          const patch: PortalUserPatch = { display_name: values.display_name ?? '', note: values.note ?? '', max_keys: values.max_keys };
          if (values.password) patch.password = values.password;
          updateUser.mutate({ id: editing.id, patch });
        }}>
          <Form.Item name="display_name" label={t('portal.display_name')}><Input /></Form.Item>
          <Form.Item name="max_keys" label={t('portal_admin.max_keys')}><InputNumber min={0} max={1000} /></Form.Item>
          <Form.Item name="note" label={t('portal_admin.col.note')}><Input.TextArea rows={2} maxLength={500} /></Form.Item>
          <Form.Item name="password" label={t('portal_admin.reset_password')} extra={t('portal_admin.reset_password_hint')} rules={[{ min: 8, message: t('portal.password_rule') }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal open={isInviting} title={t('portal_admin.invite_create')} okText={t('portal_admin.invite_create')}
        confirmLoading={createInvite.isPending} onOk={() => inviteForm.submit()} onCancel={() => setIsInviting(false)} destroyOnHidden>
        <Form form={inviteForm} layout="vertical" requiredMark={false} initialValues={{ max_uses: 1 }} onFinish={(values) => createInvite.mutate(values)}>
          <Form.Item name="max_uses" label={t('portal_admin.col.uses')}><InputNumber min={1} max={10000} /></Form.Item>
          <Form.Item name="expires" label={t('portal.col.expires')}><DatePicker disabledDate={(day) => day.isBefore(new Date(), 'day')} /></Form.Item>
          <Form.Item name="note" label={t('portal_admin.col.note')}><Input maxLength={500} /></Form.Item>
        </Form>
      </Modal>

      <Modal open={inviteCode !== undefined} title={t('portal_admin.invite_issued_title')} onCancel={() => setInviteCode(undefined)} mask={{ closable: false }}
        footer={<Button type="primary" onClick={() => setInviteCode(undefined)}>{t('portal.key_issued_done')}</Button>}>
        <Notice tone="warning" description={t('portal_admin.invite_issued_warning')} />
        <div className={styles['secret']}><span>{inviteCode}</span>{inviteCode && <CopyButton text={inviteCode} />}</div>
      </Modal>

      <PortalUserDrawer user={inspecting} onClose={() => setInspecting(undefined)} onChanged={refresh} />
    </>
  );
};

const PortalUserDrawer: React.FC<{ user?: PortalAdminUser; onClose: () => void; onChanged: () => void }> = ({ user, onClose, onChanged }) => {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const id = user?.id ?? 0;
  const keys = useQuery({ queryKey: [...PORTAL_QUERY, 'keys', id], queryFn: () => portalAdminApi.userKeys(id), enabled: id > 0 });
  const usage = useQuery({ queryKey: [...PORTAL_QUERY, 'usage', id], queryFn: () => portalAdminApi.userUsage(id, 30), enabled: id > 0 });
  const revoke = useMutation({
    mutationFn: (keyId: number) => portalAdminApi.revokeKey(keyId),
    onSuccess: () => {
      toast.success(t('portal.key_revoked'));
      void queryClient.invalidateQueries({ queryKey: [...PORTAL_QUERY, 'keys', id] });
      onChanged();
    },
    onError: (err) => toast.error(t('portal.key_revoke_failed'), { error: err }),
  });
  return (
    <AppDrawer open={user !== undefined} onClose={onClose} width="wide" title={user ? (user.display_name || user.username) : ''}>
      {user && (
        <Space orientation="vertical" size={16} style={{ width: '100%' }}>
          <Link to={`/usage/events?preset=30d&portal_user=${user.id}`}>{t('portal_admin.open_request_log')}</Link>
          {user.note && <p className={styles['muted']}>{user.note}</p>}
          <Panel title={t('portal.keys_title')}>
            {keys.isError ? <LoadFailure title={t('portal.keys_failed')} error={keys.error} onRetry={() => void keys.refetch()} /> : (
              <Table<PortalAdminKey>
                rowKey="id" size="small" pagination={false} loading={keys.isPending} dataSource={keys.data?.keys ?? []} scroll={{ x: true }}
                locale={{ emptyText: <EmptyState size="compact" title={t('portal.no_keys')} /> }}
                columns={[
                  { title: t('portal.col.name'), dataIndex: 'name' },
                  { title: t('portal.col.key'), key: 'mask', render: (_, key) => <span className={styles['mono']}>{keyMask(key)}</span> },
                  { title: t('portal.col.state'), key: 'state', render: (_, key) => <span title={key.sync_error || undefined}><KeyStateTag state={key.state} /></span> },
                  { title: t('portal.col.requests'), dataIndex: 'request_count', align: 'right', render: (v: number) => formatCount(v) },
                  { title: t('portal.col.last_used'), dataIndex: 'last_used_at_ms', render: (v?: number) => formatDateTime(v) },
                  {
                    title: '', key: 'actions', align: 'right',
                    render: (_, key) => key.status === 'active' ? (
                      <ConfirmAction title={t('portal.key_revoke_confirm', { name: key.name })} confirmLabel={t('portal.key_revoke')} isDanger
                        onConfirm={() => revoke.mutateAsync(key.id).catch(() => undefined)}>
                        <Button size="small" danger>{t('portal.key_revoke')}</Button>
                      </ConfirmAction>
                    ) : null,
                  },
                ]}
              />
            )}
          </Panel>
          {usage.isPending ? <PageLoading variant="block" /> : usage.isError ? (
            <LoadFailure title={t('portal.usage_failed')} error={usage.error} onRetry={() => void usage.refetch()} />
          ) : (
            <>
              <UsageSummary report={usage.data} showCost />
              <UsageBreakdowns report={usage.data} showCost />
            </>
          )}
        </Space>
      )}
    </AppDrawer>
  );
};

