-- Alerts carry the authority epoch current when they were raised. Telemetry re-exports recent
-- alerts in every batch; deriving the epoch at export time changed a re-sent alert's content after
-- any authority change, the collector rejected the batch as a conflict, and monitoring stopped.
-- Rows that predate this migration take the epoch current at migration time (an upper bound on
-- the epoch at which they were raised).
ALTER TABLE alerts ADD COLUMN epoch INTEGER;
UPDATE alerts SET epoch = (SELECT epoch FROM authority WHERE id = 1) WHERE epoch IS NULL;
