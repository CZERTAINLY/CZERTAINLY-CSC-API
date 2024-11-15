package com.czertainly.csc.repository;


import com.czertainly.csc.repository.entities.CredentialSessionEntity;
import org.springframework.data.repository.CrudRepository;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;

public interface CredentialSessionsRepository extends CrudRepository<CredentialSessionEntity, UUID> {

    List<CredentialSessionEntity> findByExpiresInBeforeOrderByExpiresInAsc(ZonedDateTime instant);

}
