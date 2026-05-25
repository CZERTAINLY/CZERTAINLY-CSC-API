package com.otilm.csc.repository;

import java.util.UUID;

public record ExpiredKeyCleanupView(UUID keyId, UUID credentialId, UUID sessionId) {

}
