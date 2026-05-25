package com.otilm.csc.repository;

import com.otilm.csc.repository.entities.SessionKeyEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.ZonedDateTime;
import java.util.List;

@Repository
public interface SessionKeyRepository extends KeyRepository<SessionKeyEntity> {

    /**
     * Returns all session keys acquired at or before {@code cutoff} that are marked as in-use,
     * together with their associated credential and session (either of which may be absent).
     * <p>
     * Each row contains:
     * <ul>
     *   <li>{@code keyId} — always present</li>
     *   <li>{@code credentialId} — null if the key has no associated credential</li>
     *   <li>{@code sessionId} — null if the credential has no associated session,
     *       or if the key has no credential</li>
     * </ul>
     * Results are ordered by {@code acquiredAt} ascending (oldest keys first).
     * <p>
     * The credential and session joins are intentionally left outer joins. Timely removal of
     * session keys may be a regulatory requirement, so cleanup must not be blocked by a missing
     * credential or session — whether caused by a bug or an incomplete earlier cleanup. An inner
     * join would silently exclude such keys, leaving them stuck indefinitely.
     */
    @Query("""
            SELECT new com.otilm.csc.repository.ExpiredKeyCleanupView(sk.id, sc.id, ss.id)
            FROM SessionKeyEntity sk
            LEFT JOIN SessionCredentialMetadataEntity sc ON sc.keyId = sk.id
            LEFT JOIN SigningSessionEntity ss ON ss.credentialId = sc.id
            WHERE sk.inUse = true AND sk.acquiredAt <= :cutoff
            ORDER BY sk.acquiredAt ASC
            """)
    List<ExpiredKeyCleanupView> findExpiredKeyCleanupViews(@Param("cutoff") ZonedDateTime cutoff);
}
