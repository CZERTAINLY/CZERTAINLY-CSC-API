package com.czertainly.csc.repository;


import com.czertainly.csc.repository.entities.SigningSessionEntity;
import org.springframework.data.repository.CrudRepository;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;

public interface SigningSessionsRepository extends CrudRepository<SigningSessionEntity, UUID> {

    List<SigningSessionEntity> findByExpiresInBeforeOrderByExpiresInAsc(ZonedDateTime instant);

}
