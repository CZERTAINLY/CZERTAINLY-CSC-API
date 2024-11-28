CREATE TABLE session_keys
(
    id                  uuid         primary key,
    crypto_token_id   text           not null,
    key_alias         text         not null,
    key_algorithm       text         not null,
    in_use              boolean      not null,
    acquired_at        timestamp with time zone null
);

CREATE TABLE one_time_keys
(
    id                  uuid         primary key,
    crypto_token_id   text           not null,
    key_alias         text         not null,
    key_algorithm       text         not null,
    in_use              boolean      not null,
    acquired_at        timestamp with time zone null
);

