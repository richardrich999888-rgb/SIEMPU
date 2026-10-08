-- Record the authority epoch at the time of each security alert. Telemetry export previously
-- stamped alerts with the epoch current at export time, so an alert's event changed after any
-- authority change and the collector rejected every later batch (TELEMETRY_CONFLICT).
-- Rows written before this migration get the epoch current when it is applied: approximate,
-- but fixed once, so their exported events stay identical from then on.
ALTER TABLE alerts ADD COLUMN epoch INTEGER;
UPDATE alerts SET epoch=(SELECT epoch FROM authority WHERE id=1) WHERE epoch IS NULL;
