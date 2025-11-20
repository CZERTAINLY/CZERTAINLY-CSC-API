CREATE TABLE long_term_keys
(
    id                  BINARY (16)  primary key,
    crypto_token_id     text         not null,
    key_alias           text         not null,
    key_algorithm       text         not null
);
