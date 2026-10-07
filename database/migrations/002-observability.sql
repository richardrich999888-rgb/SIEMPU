CREATE TABLE counters(name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0);
CREATE INDEX evidence_sequence ON evidence(sequence DESC);
