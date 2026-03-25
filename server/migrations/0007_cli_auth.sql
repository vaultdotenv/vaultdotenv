-- CLI auth codes for browser-based login
CREATE TABLE IF NOT EXISTS cli_auth_codes (
  code TEXT PRIMARY KEY,
  session_token TEXT,
  user_id TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cli_auth_codes_status ON cli_auth_codes(status, expires_at);
