DROP TABLE contacts;
DROP TABLE devices;
DROP TABLE sessions;
DROP TABLE invites;
DROP TABLE users;

CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE devices (
    id               BIGINT PRIMARY KEY CHECK (id BETWEEN 100000000 AND 999999999),
    public_key       BYTEA NOT NULL UNIQUE,
    fingerprint_hash TEXT NOT NULL,
    name             TEXT NOT NULL,
    disabled         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ
);

CREATE TABLE device_links (
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id  BIGINT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE contacts (
    user_id   BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id BIGINT NOT NULL CHECK (device_id BETWEEN 100000000 AND 999999999),
    alias     TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id)
);
