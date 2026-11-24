package store

// migrations[i] upgrades the schema from version i to i+1.
var migrations = []string{
	`CREATE TABLE users(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, hash TEXT NOT NULL, created_at TEXT NOT NULL, last_login TEXT);
CREATE TABLE kv(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE devices(id INTEGER PRIMARY KEY, mac TEXT UNIQUE, name TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
  known INTEGER NOT NULL DEFAULT 0, manual_type TEXT NOT NULL DEFAULT '', auto_type TEXT NOT NULL DEFAULT 'unknown',
  vendor TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '', last_ip TEXT NOT NULL, randomized INTEGER NOT NULL DEFAULT 0,
  is_self INTEGER NOT NULL DEFAULT 0, watched INTEGER NOT NULL DEFAULT 0, watch_after_s INTEGER NOT NULL DEFAULT 0,
  online INTEGER NOT NULL DEFAULT 1, ports_scanned INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE TABLE device_ports(device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, port INTEGER NOT NULL, open INTEGER NOT NULL,
  acked INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(device_id, port));
CREATE TABLE ip_history(device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ip TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(device_id, ip));
CREATE TABLE events(id INTEGER PRIMARY KEY, at TEXT NOT NULL, kind TEXT NOT NULL, device_id INTEGER, detail TEXT NOT NULL DEFAULT '', read INTEGER NOT NULL DEFAULT 0);
CREATE TABLE gateway(id INTEGER PRIMARY KEY CHECK(id=1), ip TEXT NOT NULL, mac TEXT NOT NULL, pending_mac TEXT NOT NULL DEFAULT '');
CREATE TABLE login_attempts(id INTEGER PRIMARY KEY, ip TEXT NOT NULL, at TEXT NOT NULL, success INTEGER NOT NULL);
CREATE TABLE scans(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, started TEXT NOT NULL, finished TEXT, found INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '');
CREATE INDEX events_at ON events(at);
CREATE INDEX login_attempts_ip_at ON login_attempts(ip, at);`,
	`CREATE TABLE people(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE person_devices(person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, PRIMARY KEY(person_id, device_id));
CREATE TABLE presence(id INTEGER PRIMARY KEY, person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK(state IN ('home','away')), at TEXT NOT NULL);
CREATE INDEX presence_person_at ON presence(person_id, at);
CREATE TABLE latency_5m(at TEXT NOT NULL, target TEXT NOT NULL, min_ms REAL NOT NULL, avg_ms REAL NOT NULL, max_ms REAL NOT NULL,
  jitter_ms REAL NOT NULL, loss_pct REAL NOT NULL, dns_ms REAL NOT NULL, PRIMARY KEY(at, target));
CREATE TABLE speedtests(id INTEGER PRIMARY KEY, at TEXT NOT NULL, down_mbps REAL NOT NULL DEFAULT 0, up_mbps REAL NOT NULL DEFAULT 0,
  loaded_ms REAL NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '');
CREATE INDEX speedtests_at ON speedtests(at);`,
	`ALTER TABLE devices ADD COLUMN http_info TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN is_gateway INTEGER NOT NULL DEFAULT 0;`,
}

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	if err := s.DB.QueryRow(`SELECT version FROM schema_version`).Scan(&v); err != nil {
		if _, err := s.DB.Exec(`INSERT INTO schema_version(version) VALUES (0)`); err != nil {
			return err
		}
		v = 0
	}
	for ; v < len(migrations); v++ {
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec(`UPDATE schema_version SET version = ?`, v+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
