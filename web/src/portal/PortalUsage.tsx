import React from 'react';
import { Button, Segmented, Select, Table } from 'antd';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useT } from '../i18n';
import { PageHeader } from '../components/common/PageHeader';
import { Panel } from '../components/common/Panel';
import { PageLoading } from '../components/common/PageLoading';
import { EmptyState } from '../components/common/EmptyState';
import { Tag } from '../components/common/Tag';
import { LoadFailure } from '../components/feedback';
import { portalApi } from './api';
import { usePortal } from './PortalApp';
import { formatCount, formatDateTime, formatTokens, formatUSD } from './format';
import type { PortalUsageEvent } from './types';
import styles from './Portal.module.css';

const PAGE_SIZE = 50;

/** The customer's own request records, newest first, with no routing detail. */
export const PortalUsagePage: React.FC = () => {
  const t = useT();
  const { config } = usePortal();
  const [keyId, setKeyId] = React.useState<number>();
  const [result, setResult] = React.useState<'all' | 'success' | 'failed'>('all');
  const keys = useQuery({ queryKey: ['portal', 'keys'], queryFn: portalApi.keys });
  const events = useInfiniteQuery({
    queryKey: ['portal', 'events', keyId, result],
    queryFn: ({ pageParam }) => portalApi.events({ cursor: pageParam, keyId, result, limit: PAGE_SIZE }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => (page.has_more ? page.next_cursor : undefined),
  });
  const rows = events.data?.pages.flatMap((page) => page.items) ?? [];
  const showCost = config.show_cost === true;

  return (
    <>
      <PageHeader title={t('portal.usage_title')} subtitle={t('portal.usage_subtitle')} />
      <div className={styles['toolbar']}>
        <Select<number | undefined>
          allowClear
          placeholder={t('portal.filter_all_keys')}
          value={keyId}
          onChange={(value) => setKeyId(value)}
          options={(keys.data?.keys ?? []).map((key) => ({ value: key.id, label: key.name }))}
          style={{ minWidth: 200 }}
          aria-label={t('portal.col.key')}
        />
        <Segmented
          value={result}
          onChange={(value) => setResult(value as typeof result)}
          options={[
            { value: 'all', label: t('portal.filter_all') },
            { value: 'success', label: t('portal.filter_success') },
            { value: 'failed', label: t('portal.filter_failed') },
          ]}
        />
      </div>
      <Panel>
        {events.isPending ? <PageLoading variant="block" /> : events.isError ? (
          <LoadFailure title={t('portal.usage_failed')} error={events.error} onRetry={() => void events.refetch()} />
        ) : (
          <>
            <Table<PortalUsageEvent>
              rowKey="id"
              size="small"
              dataSource={rows}
              pagination={false}
              scroll={{ x: true }}
              locale={{ emptyText: <EmptyState size="compact" title={t('portal.no_usage')} /> }}
              columns={[
                { title: t('portal.col.time'), dataIndex: 'timestamp_ms', render: (v: number) => formatDateTime(v) },
                { title: t('portal.col.key'), dataIndex: 'key_name', render: (v?: string) => v ?? '—' },
                { title: t('portal.col.model'), dataIndex: 'model', render: (v: string) => <span className={styles['mono']}>{v}</span> },
                {
                  title: t('portal.col.result'),
                  key: 'result',
                  render: (_, row) => row.failed
                    ? <Tag tone="danger" size="small">{row.status_code ? t('portal.failed_status', { code: row.status_code }) : t('portal.filter_failed')}</Tag>
                    : <Tag tone="success" size="small">{t('portal.filter_success')}</Tag>,
                },
                { title: t('portal.col.input'), dataIndex: 'input_tokens', align: 'right', render: (v: number) => formatTokens(v) },
                { title: t('portal.col.output'), dataIndex: 'output_tokens', align: 'right', render: (v: number) => formatTokens(v) },
                { title: t('portal.col.tokens'), dataIndex: 'total_tokens', align: 'right', render: (v: number) => formatTokens(v) },
                { title: t('portal.col.latency'), dataIndex: 'latency_ms', align: 'right', render: (v: number) => `${formatCount(v)} ms` },
                ...(showCost ? [{ title: t('portal.col.cost'), dataIndex: 'cost_usd', align: 'right' as const, render: (v?: number) => formatUSD(v) }] : []),
              ]}
            />
            {events.hasNextPage && (
              <div className={styles['switch-link']}>
                <Button loading={events.isFetchingNextPage} onClick={() => void events.fetchNextPage()}>{t('portal.load_more')}</Button>
              </div>
            )}
          </>
        )}
      </Panel>
      <p className={styles['muted']}>{t('portal.usage_retention_note')}</p>
    </>
  );
};
