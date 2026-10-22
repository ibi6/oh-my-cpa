package repository

// The customer portal's tables (ADR 0105) are classified here rather than in the
// shared lifecycle and query tables, so the feature's footprint in files the
// upstream also edits stays at zero lines. The tests that require every table to
// be classified read the same maps, so a portal table cannot go unclassified.
func init() {
	for table, lifecycle := range map[string]TableLifecycle{
		"portal_users":       {Kind: LifecyclePermanent, Reason: "customer accounts, removed only by the operator"},
		"portal_sessions":    {Kind: LifecycleOwnerBounded, Reason: "expired sessions are deleted by every new sign-in; an account change deletes the account's sessions"},
		"portal_invites":     {Kind: LifecyclePermanent, Reason: "operator-issued invites; the record of who could register"},
		"portal_api_keys":    {Kind: LifecyclePermanent, Reason: "request records keep the key's fingerprint and id, so its owner must stay resolvable"},
		"portal_usage_daily": {Kind: LifecyclePermanent, Reason: "each customer's usage history at the daily grain; it outlives the request records"},
	} {
		TABLE_LIFECYCLES[table] = lifecycle
	}
	QUERY_READABLE_TABLES["portal_users"] = []string{"password_hash"}
	QUERY_HIDDEN_TABLES["portal_invites"] = "invite code hashes, which a seek on the unique index would let a query test codes against"
	QUERY_READABLE_TABLES["portal_api_keys"] = nil
	QUERY_READABLE_TABLES["portal_usage_daily"] = nil
	QUERY_HIDDEN_TABLES["portal_sessions"] = "customer session token hashes, which identify live sign-ins"
}
