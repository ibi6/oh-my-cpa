package repository

import (
	"context"
	"fmt"
	"strconv"
)

// PortalUsageMeasures is one rollup row of a customer's usage.
type PortalUsageMeasures struct {
	Requests        int64 `json:"requests"`
	FailedRequests  int64 `json:"failed_requests"`
	InputTokens     int64 `json:"input_tokens"`
	OutputTokens    int64 `json:"output_tokens"`
	ReasoningTokens int64 `json:"reasoning_tokens"`
	CachedTokens    int64 `json:"cached_tokens"`
	TotalTokens     int64 `json:"total_tokens"`
	CostNanos       int64 `json:"-"`
}

// PortalUsageGroup is one group of a rollup: a UTC day, a model or a key.
type PortalUsageGroup struct {
	DayStartMS int64  `json:"day_start_ms,omitempty"`
	Model      string `json:"model,omitempty"`
	KeyID      int64  `json:"key_id,omitempty"`
	PortalUsageMeasures
}

// Portal usage groupings; the grouping expression comes from this closed set,
// never from a caller.
const (
	PortalUsageByDay   = "day"
	PortalUsageByModel = "model"
	PortalUsageByKey   = "key"
)

var portalUsageGroupColumns = map[string]string{
	PortalUsageByDay:   "day_start_ms",
	PortalUsageByModel: "model",
	PortalUsageByKey:   "key_id",
}

const portalUsageMeasureSQL = `COALESCE(SUM(requests), 0), COALESCE(SUM(failed_requests), 0),
	COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), COALESCE(SUM(reasoning_tokens), 0),
	COALESCE(SUM(cached_tokens), 0), COALESCE(SUM(total_tokens), 0), COALESCE(SUM(cost_nanos), 0)`

func portalMeasureTargets(m *PortalUsageMeasures) []any {
	return []any{&m.Requests, &m.FailedRequests, &m.InputTokens, &m.OutputTokens, &m.ReasoningTokens,
		&m.CachedTokens, &m.TotalTokens, &m.CostNanos}
}

// PortalUsageRollup totals one account's permanent daily rollup over the UTC
// days starting in [fromDayMS, toDayMS], grouped by day, model or key. userID
// zero totals every account (the operator's overview).
func (r *Repository) PortalUsageRollup(ctx context.Context, userID int64, fromDayMS, toDayMS int64, groupBy string) ([]PortalUsageGroup, error) {
	db, err := r.portalDB()
	if err != nil {
		return nil, err
	}
	column, ok := portalUsageGroupColumns[groupBy]
	if !ok {
		return nil, fmt.Errorf("unknown portal usage grouping %q", groupBy)
	}
	where := `day_start_ms BETWEEN ? AND ?`
	args := []any{fromDayMS, toDayMS}
	if userID > 0 {
		where = `user_id = ? AND ` + where
		args = append([]any{userID}, args...)
	}
	rows, err := db.QueryContext(ctx, `SELECT `+column+`, `+portalUsageMeasureSQL+`
		FROM portal_usage_daily WHERE `+where+` GROUP BY `+column+` ORDER BY `+column+` ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("read portal usage: %w", err)
	}
	defer rows.Close()
	items := []PortalUsageGroup{}
	for rows.Next() {
		var item PortalUsageGroup
		targets := portalMeasureTargets(&item.PortalUsageMeasures)
		switch groupBy {
		case PortalUsageByDay:
			targets = append([]any{&item.DayStartMS}, targets...)
		case PortalUsageByModel:
			targets = append([]any{&item.Model}, targets...)
		case PortalUsageByKey:
			targets = append([]any{&item.KeyID}, targets...)
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, fmt.Errorf("scan portal usage: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// PortalUsageTotals totals one account's permanent rollup over its whole life.
func (r *Repository) PortalUsageTotals(ctx context.Context, userID int64) (PortalUsageMeasures, error) {
	var totals PortalUsageMeasures
	db, err := r.portalDB()
	if err != nil {
		return totals, err
	}
	err = db.QueryRowContext(ctx, `SELECT `+portalUsageMeasureSQL+` FROM portal_usage_daily WHERE user_id = ?`, userID).
		Scan(portalMeasureTargets(&totals)...)
	return totals, err
}

// PortalRecentUsage totals one account's request records in [fromMS, toMS]. It
// reads usage_events, so it is exact to the millisecond but limited to the
// records retention still holds; it is for short windows such as "last 24h".
func (r *Repository) PortalRecentUsage(ctx context.Context, userID, fromMS, toMS int64) (PortalUsageMeasures, error) {
	var totals PortalUsageMeasures
	db, err := r.portalDB()
	if err != nil {
		return totals, err
	}
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(1), COALESCE(SUM(failed <> 0), 0), COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0),
		       COALESCE(SUM(reasoning_tokens), 0), COALESCE(SUM(cached_tokens), 0), COALESCE(SUM(total_tokens), 0),
		       COALESCE(SUM(cost_nanos), 0)
		FROM usage_events WHERE portal_user_id = ? AND timestamp_ms BETWEEN ? AND ?`, userID, fromMS, toMS).
		Scan(portalMeasureTargets(&totals)...)
	return totals, err
}

// PortalUserFacet lists the portal accounts that made requests in a window, as
// a request-record facet: the value is the account id the `portal_user` filter
// takes, the alias its username.
func (r *Repository) PortalUserFacet(ctx context.Context, instanceID string, fromMS, toMS int64) ([]UsageFacetValue, error) {
	db, err := r.portalDB()
	if err != nil {
		return []UsageFacetValue{}, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT e.portal_user_id, COUNT(1) AS requests, COALESCE(MAX(u.username), '')
		FROM usage_events e LEFT JOIN portal_users u ON u.id = e.portal_user_id
		WHERE e.instance_id = ? AND e.timestamp_ms BETWEEN ? AND ? AND e.portal_user_id IS NOT NULL
		GROUP BY e.portal_user_id ORDER BY requests DESC, e.portal_user_id ASC LIMIT 200`, instanceID, fromMS, toMS)
	if err != nil {
		return []UsageFacetValue{}, fmt.Errorf("read portal user facet: %w", err)
	}
	defer rows.Close()
	items := []UsageFacetValue{}
	for rows.Next() {
		var id int64
		var item UsageFacetValue
		if err := rows.Scan(&id, &item.Requests, &item.Alias); err != nil {
			return []UsageFacetValue{}, err
		}
		item.Value = strconv.FormatInt(id, 10)
		items = append(items, item)
	}
	return items, rows.Err()
}
