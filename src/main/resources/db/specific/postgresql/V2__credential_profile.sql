ALTER TABLE credentials
    ADD COLUMN credential_profile text NULL;

UPDATE credentials
SET credential_profile = 'default'
WHERE credential_profile IS NULL;

ALTER TABLE credentials
    ALTER COLUMN credential_profile SET NOT NULL;