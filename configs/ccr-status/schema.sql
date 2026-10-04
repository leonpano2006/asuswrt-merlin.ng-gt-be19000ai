PRAGMA journal_mode=MEMORY;
PRAGMA synchronous=OFF;
PRAGMA max_page_count=256;
CREATE TABLE IF NOT EXISTS DB_INFO (info_name TEXT NOT NULL, info_value TEXT NOT NULL);
INSERT INTO DB_INFO SELECT 'db_version','1.0' WHERE NOT EXISTS (SELECT 1 FROM DB_INFO);
-- One bounded snapshot; no SQL NULL values reach the stock libcodb serializer.
CREATE TABLE IF NOT EXISTS DATA_INFO (
 data_id INTEGER PRIMARY KEY, data_time TIMESTAMP NOT NULL, payload TEXT NOT NULL
);
