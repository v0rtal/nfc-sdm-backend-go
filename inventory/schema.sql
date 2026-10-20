CREATE TABLE IF NOT EXISTS inventory_schema (version integer PRIMARY KEY);
CREATE TABLE IF NOT EXISTS tags (
 uid text PRIMARY KEY CHECK (uid ~ '^[0-9A-F]{14}$'),
 name text NOT NULL DEFAULT '', description text NOT NULL DEFAULT '',
 attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
 first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
 max_counter integer CHECK (max_counter BETWEEN 0 AND 16777215),
 scan_count bigint NOT NULL DEFAULT 0, request_count bigint NOT NULL DEFAULT 0,
 tamper_status text NOT NULL DEFAULT '', enc_mode text NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scans (
 uid text NOT NULL REFERENCES tags(uid), counter integer NOT NULL CHECK (counter BETWEEN 0 AND 16777215),
 first_seen timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 opens bigint NOT NULL DEFAULT 1, PRIMARY KEY(uid,counter)
);
ALTER TABLE tags ADD COLUMN IF NOT EXISTS tamper_detected_at timestamptz;
CREATE TABLE IF NOT EXISTS scan_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 uid text NOT NULL REFERENCES tags(uid), counter integer,
 viewed_at timestamptz NOT NULL, status text NOT NULL, tamper_status text NOT NULL
);
CREATE INDEX IF NOT EXISTS scan_events_tag_time ON scan_events(uid,id DESC);
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS client_ip text NOT NULL DEFAULT '';
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS location jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE TABLE IF NOT EXISTS item_images (
 id text PRIMARY KEY, uid text NOT NULL REFERENCES tags(uid),
 mime text NOT NULL CHECK (mime IN ('image/jpeg','image/png')),
 data bytea NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 5242880),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS item_images_tag ON item_images(uid,created_at);
INSERT INTO inventory_schema(version) VALUES(1) ON CONFLICT DO NOTHING;
INSERT INTO inventory_schema(version) VALUES(2) ON CONFLICT DO NOTHING;
UPDATE tags SET tamper_detected_at=history.detected_at
FROM (SELECT uid,min(viewed_at) AS detected_at FROM scan_events WHERE tamper_status IN ('tampered_closed','tampered_open') GROUP BY uid) AS history
WHERE tags.uid=history.uid AND tags.tamper_detected_at IS NULL
AND NOT EXISTS (SELECT 1 FROM inventory_schema WHERE version=3);
INSERT INTO inventory_schema(version) VALUES(3) ON CONFLICT DO NOTHING;
