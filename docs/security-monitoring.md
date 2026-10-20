# Security monitoring

Persisted data includes authentication events (unknown accounts use a safe hint and may have no user), risk events, repeated-failure alerts and audit events for alert lifecycle changes. Regular accounts receive only user-scoped monitoring data. Admins can view global events and alert records; admin status is verified on every backend request. Alerts support filtering/pagination and OPEN → ACKNOWLEDGED → RESOLVED state transitions; resolved alerts cannot be reopened. Dashboard values come from live APIs, and failures display errors instead of fabricated metrics.

The heuristic does not include IP reputation, geographic anomaly detection, behavioral ML, distributed correlation or incident-response workflows. Rate limits and preauth challenges are process-local. Events are not a complete audit/SIEM trail.
