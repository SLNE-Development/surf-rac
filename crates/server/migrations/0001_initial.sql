CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE invites (
    id         BIGSERIAL PRIMARY KEY,
    code_hash  BYTEA NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    used_by    BIGINT REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE sessions (
    token_hash   BYTEA PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX sessions_user_id ON sessions (user_id);

CREATE TABLE devices (
    id               BIGINT PRIMARY KEY CHECK (id BETWEEN 100000000 AND 999999999),
    user_id          BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    fingerprint_hash TEXT NOT NULL,
    secret_hash      BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ
);

CREATE INDEX devices_user_fingerprint ON devices (user_id, fingerprint_hash);

CREATE TABLE contacts (
    user_id   BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id BIGINT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    alias     TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX contacts_device_id ON contacts (device_id);
