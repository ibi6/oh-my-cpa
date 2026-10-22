import React from 'react';
import { Segmented, Table } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { useT } from '../i18n';
import { PageHeader } from '../components/common/PageHeader';
import { Panel } from '../components/common/Panel';
import { PageLoading } from '../components/common/PageLoading';
import { EmptyState } from '../components/common/EmptyState';
import { LoadFailure, Notice } from '../components/feedback';
import { CopyButton } from '../components/common/CopyButton';
import { portalApi } from './api';
import { usePortal } from './PortalApp';
import { formatCount, formatTokens, formatUSD, formatUTCDay } from './format';
import type { PortalUsageGroup, PortalUsageMeasures, PortalUsageReport } from './types';
import styles from './Portal.module.css';

export const Stat: React.FC<{ label: React.ReactNode; value: React.ReactNode; meta?: React.ReactNode }> = ({ label, value, meta }) => (
  <Panel>
    <div className={styles['stat-label']}>{label}</div>
    <div className={styles['stat-value']}>{value}</div>
    {meta !== undefined && <div className={styles['stat-meta']}>{meta}</div>}
  </Panel>
);

/** The headline numbers of a usage report; shared by the customer's overview and the operator's drawer. */
export const UsageSummary: React.FC<{ report: PortalUsageReport; showCost: boolean }> = ({ report, showCost }) => {
  const t = useT();
  const measures = (m: PortalUsageMeasures) => t('portal.stat.tokens_meta', {
    input: formatTokens(m.input_tokens), output: formatTokens(m.output_tokens),
  });
  return (
    <div className={styles['stats']}>
      <Stat label={t('portal.stat.requests_window', { days: report.window.days })} value={formatCount(report.totals.requests)}
        meta={t('portal.stat.failed', { n: formatCount(report.totals.failed_requests) })} />
      <Stat label={t('portal.stat.tokens_window', { days: report.window.days })} value={formatTokens(report.totals.total_tokens)} meta={measures(report.totals)} />
      {showCost && <Stat label={t('portal.stat.cost_window', { days: report.window.days })} value={formatUSD(report.totals.cost_usd)} />}
      <Stat label={t('portal.stat.last_24h')} value={formatCount(report.last_24h.requests)} meta={t('portal.stat.tokens_short', { n: formatTokens(report.last_24h.total_tokens) })} />
      <Stat label={t('portal.stat.lifetime')} value={formatCount(report.lifetime.requests)} meta={t('portal.stat.tokens_short', { n: formatTokens(report.lifetime.total_tokens) })} />
    </div>
  );
};

/** The day, model and key breakdowns of a usage report. */
export const UsageBreakdowns: React.FC<{ report: PortalUsageReport; showCost: boolean }> = ({ report, showCost }) => {
  const t = useT();
  const measureColumns = [
    { title: t('portal.col.requests'), dataIndex: 'requests', align: 'right' as const, render: (v: number) => formatCount(v) },
    { title: t('portal.col.tokens'), dataIndex: 'total_tokens', align: 'right' as const, render: (v: number) => formatTokens(v) },
    ...(showCost ? [{ title: t('portal.col.cost'), dataIndex: 'cost_usd', align: 'right' as const, render: (v?: number) => formatUSD(v) }] : []),
  ];
  const daily = [...report.daily].sort((a, b) => (b.day_start_ms ?? 0) - (a.day_start_ms ?? 0));
  return (
    <>
      <div className={styles['grid-two']}>
        <Panel title={t('portal.by_model')}>
          <Table<PortalUsageGroup>
            size="small" pagination={false} rowKey={(row) => row.model ?? ''} dataSource={report.models}
            locale={{ emptyText: <EmptyState size="compact" title={t('portal.no_usage')} /> }}
            columns={[{ title: t('portal.col.model'), dataIndex: 'model', render: (v: string) => <span className={styles['mono']}>{v || '—'}</span> }, ...measureColumns]}
          />
        </Panel>
        <Panel title={t('portal.by_key')}>
          <Table<PortalUsageGroup>
            size="small" pagination={false} rowKey={(row) => String(row.key_id)} dataSource={report.keys}
            locale={{ emptyText: <EmptyState size="compact" title={t('portal.no_usage')} /> }}
            columns={[{ title: t('portal.col.key'), dataIndex: 'key_name', render: (v: string, row) => v || `#${row.key_id}` }, ...measureColumns]}
          />
        </Panel>
      </div>
      <Panel title={t('portal.by_day')}>
        <Table<PortalUsageGroup>
          size="small" pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
          rowKey={(row) => String(row.day_start_ms)} dataSource={daily}
          locale={{ emptyText: <EmptyState size="compact" title={t('portal.no_usage')} /> }}
          columns={[
            { title: t('portal.col.day_utc'), dataIndex: 'day_start_ms', render: (v: number) => formatUTCDay(v) },
            { title: t('portal.col.failed'), dataIndex: 'failed_requests', align: 'right' as const, render: (v: number) => formatCount(v) },
            ...measureColumns,
          ]}
        />
      </Panel>
    </>
  );
};

const DAY_OPTIONS = [7, 30, 90];

export const PortalOverviewPage: React.FC = () => {
  const t = useT();
  const { user, config } = usePortal();
  const [days, setDays] = React.useState(30);
  const usage = useQuery({ queryKey: ['portal', 'usage', days], queryFn: () => portalApi.usage(days) });
  const showCost = config.show_cost === true;
  return (
    <>
      <PageHeader
        title={t('portal.overview_title', { name: user.display_name || user.username })}
        subtitle={t('portal.overview_subtitle')}
        actions={<Segmented value={days} onChange={(v) => setDays(Number(v))} options={DAY_OPTIONS.map((d) => ({ value: d, label: t('portal.days', { n: d }) }))} />}
      />
      {config.gateway_url ? (
        <Panel title={t('portal.gateway_title')}>
          <p className={styles['muted']}>{t('portal.gateway_hint')}</p>
          <div className={styles['secret']}>
            <span>{config.gateway_url}</span>
            <CopyButton text={config.gateway_url} />
          </div>
        </Panel>
      ) : null}
      {usage.isPending ? <PageLoading variant="block" /> : usage.isError ? (
        <LoadFailure title={t('portal.usage_failed')} error={usage.error} onRetry={() => void usage.refetch()} />
      ) : (
        <>
          {usage.data.lifetime.requests === 0 && (
            <Notice tone="info" title={t('portal.first_steps_title')} description={<>{t('portal.first_steps_body')} <Link to="/keys">{t('portal.nav.keys')}</Link></>} />
          )}
          <UsageSummary report={usage.data} showCost={showCost} />
          <UsageBreakdowns report={usage.data} showCost={showCost} />
          <p className={styles['muted']}>{t('portal.utc_note')}</p>
        </>
      )}
    </>
  );
};
