-- ASUS libcodb passes SQL NULL to json_object_new_string without a guard.
-- Missing values use sentinels; the UI turns these into explicit chart gaps.
PRAGMA journal_mode=MEMORY;
PRAGMA synchronous=OFF;
PRAGMA max_page_count=8192;
CREATE TABLE IF NOT EXISTS DB_INFO (info_name TEXT, info_value TEXT);
INSERT INTO DB_INFO SELECT 'db_version','1.0' WHERE NOT EXISTS (SELECT 1 FROM DB_INFO);
CREATE TABLE IF NOT EXISTS DATA_INFO (
 data_id INTEGER PRIMARY KEY AUTOINCREMENT,
 kind TEXT NOT NULL, iface TEXT NOT NULL, band INTEGER NOT NULL DEFAULT -1,
 uptime REAL NOT NULL, rx_bytes REAL NOT NULL DEFAULT -1, tx_bytes REAL NOT NULL DEFAULT -1, rx_mbps REAL NOT NULL DEFAULT -1, tx_mbps REAL NOT NULL DEFAULT -1,
 links INTEGER NOT NULL DEFAULT -1, chspec TEXT NOT NULL DEFAULT '', busy REAL NOT NULL DEFAULT -1, obss REAL NOT NULL DEFAULT -1, nopkt REAL NOT NULL DEFAULT -1, noise INTEGER NOT NULL DEFAULT -999, radio_on INTEGER NOT NULL DEFAULT -1,
 data_time TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS node_stats_time ON DATA_INFO(data_time);
