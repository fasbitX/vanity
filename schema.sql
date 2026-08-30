-- Schema for the "vanity" database.
--
-- One table. A vanity address is a self-contained result: the pattern that was
-- asked for, the address that came back, and the key that produces it. There is
-- nothing to join to.
--
-- NOTE: private keys are stored in the clear. This is a search tool, not a
-- wallet. Anything holding real funds needs an encrypted keystore.

CREATE TABLE IF NOT EXISTS vanity_matches (
    id                      bigserial PRIMARY KEY,

    -- The pattern as it was given, and how it was interpreted.
    pattern                 text        NOT NULL,
    match_mode              text        NOT NULL
                            CHECK (match_mode IN ('prefix', 'prefix-ci', 'regex')),

    -- Which engine found it, and which public-key encoding the address is for.
    -- vanitygen only ever searched the uncompressed form; the GPU searches both.
    engine                  text        NOT NULL
                            CHECK (engine IN ('vanitygen', 'gpu')),
    form                    text        NOT NULL
                            CHECK (form IN ('uncompressed', 'compressed')),

    address                 text        NOT NULL,
    private_key_hex         char(64)    NOT NULL,
    wif_uncompressed        text        NOT NULL,
    wif_compressed          text        NOT NULL,
    public_key_uncompressed char(130)   NOT NULL,

    -- Expected keys for this pattern, and what the run actually cost. Together
    -- these say whether a search ran long or short for its difficulty.
    difficulty              double precision,
    seconds                 double precision,

    found_at                timestamptz NOT NULL DEFAULT now(),

    -- Which implementation confirmed the address before this row was written.
    -- Neither vanitygen nor the GPU gets in here on its own say-so.
    verified_by             text        NOT NULL DEFAULT 'src/keys.js',

    -- The same key found twice for two patterns is not a second result.
    CONSTRAINT vanity_matches_privkey_unique UNIQUE (private_key_hex),

    -- Structural guards: cheap insurance against a malformed writer.
    CONSTRAINT vanity_matches_privkey_hex_format
        CHECK (private_key_hex ~ '^[0-9a-f]{64}$'),
    CONSTRAINT vanity_matches_privkey_nonzero
        CHECK (private_key_hex <> repeat('0', 64)),
    CONSTRAINT vanity_matches_pubkey_format
        CHECK (public_key_uncompressed ~ '^04[0-9a-f]{128}$'),
    CONSTRAINT vanity_matches_address_format
        CHECK (address ~ '^1[123456789A-HJ-NP-Za-km-z]{25,34}$'),
    CONSTRAINT vanity_matches_wif_uncompressed_format
        CHECK (wif_uncompressed ~ '^5[123456789A-HJ-NP-Za-km-z]{50}$'),
    CONSTRAINT vanity_matches_wif_compressed_format
        CHECK (wif_compressed ~ '^[KL][123456789A-HJ-NP-Za-km-z]{51}$'),

    -- The address must actually begin with the prefix it was found for. A regex
    -- is not checkable in SQL, so that mode is exempt.
    CONSTRAINT vanity_matches_address_has_prefix
        CHECK (match_mode = 'regex'
               OR (match_mode = 'prefix'    AND address LIKE pattern || '%')
               OR (match_mode = 'prefix-ci' AND lower(address) LIKE lower(pattern) || '%'))
);

CREATE INDEX IF NOT EXISTS vanity_matches_pattern_idx ON vanity_matches (pattern);
CREATE INDEX IF NOT EXISTS vanity_matches_address_idx ON vanity_matches (address);
CREATE INDEX IF NOT EXISTS vanity_matches_engine_idx  ON vanity_matches (engine);
