CREATE TABLE long_term_keys
(
    id                  uuid         primary key,
    crypto_token_id     int          not null,
    key_alias           text         not null,
    key_algorithm       text         not null
);
