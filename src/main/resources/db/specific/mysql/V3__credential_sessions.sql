CREATE TABLE session_credentials
(
    id                         BINARY (16) primary key,
    user_id                    text    not null,
    key_alias                  text    not null,
    crypto_token_name          text    not null,
    end_entity_name            text    not null,
    signature_qualifier        text    null,
    multisign                  int     not null
);

CREATE TABLE credential_sessions
(
    id              BINARY (16) primary key,
    credential_id   BINARY (16) not null,
    expires_in      timestamp not null,
    FOREIGN KEY (credential_id) REFERENCES session_credentials(id)
);