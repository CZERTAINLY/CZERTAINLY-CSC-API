CREATE TABLE credentials
(
    id                         BINARY(16) primary key,
    user_id                    text    not null,
    key_alias                  text    not null,
    crypto_token_name          text    not null,
    end_entity_name            text    not null,
    current_certificate_sn     text    not null,
    current_certificate_issuer text    not null,
    signature_qualifier        text    null,
    description                text    null,
    multisign                  int     not null,
    scal                       text    null,
    disabled                   boolean not null
);