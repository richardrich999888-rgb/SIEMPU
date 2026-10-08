-- Public endpoint keys only. Private encryption/signing handles remain on clients.
CREATE TABLE crypto_keys (
  key_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id),
  descriptor TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','active','retired','revoked')),
  created_at INTEGER NOT NULL
);
CREATE TABLE crypto_policy (
  id INTEGER PRIMARY KEY CHECK(id=1),
  value TEXT NOT NULL
);
INSERT INTO crypto_policy VALUES(1,'{"schemaVersion":1,"revision":1,"mode":"production","newSuites":[{"providerId":"siepmu-webcrypto-p256-v1","suiteId":"P256-HKDF-SHA256-AES256GCM"}],"legacySuites":[{"providerId":"siepmu-webcrypto-p256-v1","suiteId":"P256-HKDF-SHA256-AES256GCM"}]}');
