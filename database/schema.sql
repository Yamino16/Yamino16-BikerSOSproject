-- Schema ricostruito dalle query del backend (backend/index.php).
-- Il database di produzione (PostgreSQL su Neon) resta il riferimento.

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL
);

-- L'id del profilo è un UUID: compare nel link pubblico /emergency/:uuid
-- associato al bracciale NFC.
CREATE TABLE profiles (
    id          UUID PRIMARY KEY,
    user_id     INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    name        VARCHAR(255),
    dob         DATE,
    photo_url   TEXT,
    blood_type  VARCHAR(5),
    ice_name    VARCHAR(255),
    ice_phone   VARCHAR(50),
    allergies   TEXT,
    conditions  TEXT,
    medications TEXT,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id                   SERIAL PRIMARY KEY,
    user_id              INTEGER REFERENCES users(id),
    stripe_session_id    VARCHAR(255) NOT NULL UNIQUE,
    customer_email       VARCHAR(255),
    shipping_name        VARCHAR(255),
    shipping_address     VARCHAR(255),
    shipping_city        VARCHAR(255),
    shipping_postal_code VARCHAR(20),
    shipping_country     VARCHAR(2),
    amount_total         INTEGER,
    created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
