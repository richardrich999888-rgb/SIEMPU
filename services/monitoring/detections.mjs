// Applicant-defined laboratory rules over authenticated, redacted security signals.
// Counts are distinct telemetry records, not distinct people, login attempts or incidents.
import { canonical, hash, packet } from '../control/primitives.mjs';

export const WINDOW_MS = 60000;
export const DETECTION_RULES = Object.freeze([
  Object.freeze({ id: 'AUTH_FAILURE_SIGNALS', eventType: 'AUTH_FAILURE', threshold: 5 }),
  Object.freeze({ id: 'ACCESS_DENIAL_SIGNALS', eventType: 'ACCESS_DENIED', threshold: 3 }),
  Object.freeze({ id: 'RELEASE_DENIAL_SIGNALS', eventType: 'RELEASE_DENIED', threshold: 3 }),
]);
const DISPOSITIONS = new Set(['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE']);

// Uses the collector's transaction. Never opens or commits a transaction independently.
export class ThreatDetections {
  constructor({ db, signingKey, sourceKey, maxBuckets = 32768, maxDetections = 10000 }) {
    for (const limit of [maxBuckets, maxDetections])
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100000)
        throw new Error('DETECTION_LIMIT_CONFIG');
    Object.assign(this, { db, signingKey, maxBuckets, maxDetections });
    this.sourceId = hash(canonical(sourceKey));
    const profileId = hash(canonical({ version: 1, windowMs: WINDOW_MS, rules: DETECTION_RULES }));
    db.exec(`CREATE TABLE IF NOT EXISTS threat_buckets(
      rule TEXT NOT NULL, start INTEGER NOT NULL, count INTEGER NOT NULL,
      first_at INTEGER NOT NULL, last_at INTEGER NOT NULL, emitted INTEGER NOT NULL,
      PRIMARY KEY(rule,start));
      CREATE TABLE IF NOT EXISTS detections(
      id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, record TEXT NOT NULL, ack TEXT);
      CREATE INDEX IF NOT EXISTS detections_created ON detections(created_at);
      CREATE TABLE IF NOT EXISTS detection_configuration(
      id INTEGER PRIMARY KEY CHECK(id=1), source_id TEXT NOT NULL, profile_id TEXT NOT NULL);`);
    // A source/rule change needs an explicit migration, not reuse of another source's counters.
    const prior = db.prepare('SELECT * FROM detection_configuration WHERE id=1').get();
    if (
      !prior &&
      (db.prepare('SELECT count(*) AS n FROM threat_buckets').get().n !== 0 ||
        db.prepare('SELECT count(*) AS n FROM detections').get().n !== 0)
    )
      throw new Error('DETECTION_CONFIG_MISSING');
    db.prepare('INSERT OR IGNORE INTO detection_configuration VALUES(1,?,?)').run(
      this.sourceId,
      profileId,
    );
    const configured = db.prepare('SELECT * FROM detection_configuration WHERE id=1').get();
    if (configured.source_id !== this.sourceId || configured.profile_id !== profileId)
      throw new Error('DETECTION_CONFIG_MISMATCH');
  }
  prune(now, retentionMs) {
    // Open and investigating detections are never silently evicted to admit more traffic.
    this.db
      .prepare(
        "DELETE FROM detections WHERE created_at<? AND json_extract(ack,'$.payload.disposition') IN ('RESOLVED','FALSE_POSITIVE')",
      )
      .run(now - retentionMs);
    this.db.prepare('DELETE FROM threat_buckets WHERE start+?<?').run(WINDOW_MS, now - retentionMs);
  }
  observe(event, now) {
    const rule = DETECTION_RULES.find((r) => r.eventType === event.eventType);
    if (!rule) return;
    const start = Math.floor(event.timestamp / WINDOW_MS) * WINDOW_MS;
    const old = this.db
      .prepare('SELECT * FROM threat_buckets WHERE rule=? AND start=?')
      .get(rule.id, start);
    if (
      !old &&
      this.db.prepare('SELECT count(*) AS n FROM threat_buckets').get().n >= this.maxBuckets
    )
      throw new Error('DETECTION_BUCKET_CAPACITY');
    this.db
      .prepare(
        `INSERT INTO threat_buckets VALUES(?,?,1,?,?,0)
      ON CONFLICT(rule,start) DO UPDATE SET count=count+1,
      first_at=min(first_at,excluded.first_at),last_at=max(last_at,excluded.last_at)`,
      )
      .run(rule.id, start, event.timestamp, event.timestamp);
    const bucket = this.db
      .prepare('SELECT * FROM threat_buckets WHERE rule=? AND start=?')
      .get(rule.id, start);
    if (bucket.emitted || bucket.count < rule.threshold) return;
    if (this.db.prepare('SELECT count(*) AS n FROM detections').get().n >= this.maxDetections)
      throw new Error('DETECTION_CAPACITY');
    const id = hash(
      canonical({ domain: 'SIEPMU_DETECTION_V1', sourceId: this.sourceId, rule: rule.id, start }),
    );
    const detection = packet(this.signingKey, {
      version: 1,
      kind: 'SIEPMU_THREAT_SIGNAL',
      detectionId: id,
      sourceId: this.sourceId,
      ruleId: rule.id,
      ruleVersion: 1,
      windowStart: start,
      windowEnd: start + WINDOW_MS,
      threshold: rule.threshold,
      observedSignals: bucket.count,
      firstEventAt: bucket.first_at,
      lastEventAt: bucket.last_at,
      triggerEventId: event.eventId,
      detectedAt: now,
    });
    this.db.prepare('INSERT INTO detections VALUES(?,?,?,NULL)').run(id, now, canonical(detection));
    this.db
      .prepare('UPDATE threat_buckets SET emitted=1 WHERE rule=? AND start=?')
      .run(rule.id, start);
  }
  list() {
    return this.db
      .prepare(
        `SELECT record,ack FROM detections
      ORDER BY (ack IS NOT NULL),created_at,id LIMIT 2000`,
      )
      .all()
      .map((r) => ({ detection: JSON.parse(r.record), ack: r.ack ? JSON.parse(r.ack) : null }));
  }
  acknowledge({ detectionId, disposition }, operator, now = Date.now()) {
    if (!/^[a-f0-9]{64}$/.test(detectionId) || !DISPOSITIONS.has(disposition))
      throw new Error('DETECTION_ACK_SCHEMA');
    const receipt = packet(this.signingKey, {
      version: 1,
      kind: 'SIEPMU_DETECTION_ACK',
      detectionId,
      disposition,
      operator,
      timestamp: now,
    });
    if (
      this.db.prepare('UPDATE detections SET ack=? WHERE id=?').run(canonical(receipt), detectionId)
        .changes !== 1
    )
      throw new Error('DETECTION_NOT_FOUND');
    return receipt;
  }
}
