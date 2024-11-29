CREATE TABLE session_credentials
(
    id                         uuid primary key,
    user_id                    text    not null,
    key_alias                  text    not null,
    key_id                     uuid    not null references session_keys(id),
    crypto_token_name          text    not null,
    end_entity_name            text    not null,
    signature_qualifier        text    null,
    multisign                  int     not null
);

CREATE TABLE signing_sessions
(
    id              uuid primary key,
    credential_id   uuid    not null references session_credentials(id),
    expires_in      timestamp with time zone not null
);