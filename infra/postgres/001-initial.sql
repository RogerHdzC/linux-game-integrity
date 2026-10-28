CREATE TABLE IF NOT EXISTS lgi_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS lgi_enrollments (
  id uuid PRIMARY KEY, principal text NOT NULL, public_key text NOT NULL,
  provenance text NOT NULL CHECK (provenance = 'UNPROVEN'),
  revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS lgi_challenges (
  id uuid PRIMARY KEY, enrollment_id uuid NOT NULL REFERENCES lgi_enrollments(id),
  principal text NOT NULL, nonce char(64) NOT NULL, policy_version text NOT NULL,
  expires_at timestamptz NOT NULL, consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS lgi_challenges_principal ON lgi_challenges(principal, created_at);
CREATE TABLE IF NOT EXISTS lgi_evaluations (
  id uuid PRIMARY KEY, challenge_id uuid NOT NULL UNIQUE REFERENCES lgi_challenges(id),
  principal text NOT NULL, policy_version text NOT NULL, result text NOT NULL
    CHECK (result IN ('ACCEPTED','REJECTED','INDETERMINATE')),
  checks jsonb NOT NULL, reasons jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO lgi_migrations(version) VALUES(1) ON CONFLICT DO NOTHING;
