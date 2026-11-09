-- Signed state/head binding written in the same transaction as authorization mutations.
-- Existing histories are intentionally NOT backfilled or trusted by this migration.
CREATE TABLE authorization_commit (
  id INTEGER PRIMARY KEY CHECK(id=1),
  seal TEXT NOT NULL
);
