package com.czertainly.csc.service.credentials;

import java.time.ZonedDateTime;
import java.util.UUID;

public record CredentialSession(UUID id, UUID credentialId, ZonedDateTime getExpiresIn) {}