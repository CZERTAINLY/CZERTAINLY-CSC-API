CREATE TABLE session_keys
(
    id                  BINARY (16)  primary key,
    crypto_token_id     text         not null,
    key_alias           text         not null,
    key_algorithm       text         not null,
    in_use              boolean      not null,
    acquired_at         timestamp    null
);

CREATE TABLE one_time_keys
(
    id                  BINARY (16)  primary key,
    crypto_token_id     text         not null,
    key_alias           text         not null,
    key_algorithm       text         not null,
    in_use              boolean      not null,
    acquired_at         timestamp    null
);