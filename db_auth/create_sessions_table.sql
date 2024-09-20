CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id uuid NOT NULL,
    refresh_hash varchar(100) NOT NULL,
    expire_at timestamp NOT NULL,
    access_id varchar(64) NOT NULL,         -- Access key ID
    closed boolean NOT NULL DEFAULT False   -- Was the session ended?
);
