-- Provisional laboratory dual-control policy; sponsor acceptance is outstanding.
CREATE TABLE release_approvals(
 object_id TEXT PRIMARY KEY REFERENCES objects(id),
 envelope_digest TEXT NOT NULL,
 epoch INTEGER NOT NULL,
 approver_id TEXT NOT NULL REFERENCES users(id),
 device_id TEXT NOT NULL REFERENCES devices(id),
 approved_at INTEGER NOT NULL,
 receipt TEXT NOT NULL
);
