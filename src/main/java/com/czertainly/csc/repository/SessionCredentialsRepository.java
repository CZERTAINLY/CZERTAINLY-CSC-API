package com.czertainly.csc.repository;


import com.czertainly.csc.repository.entities.SessionCredentialMetadataEntity;
import org.springframework.data.repository.CrudRepository;

import java.util.UUID;

public interface SessionCredentialsRepository extends CrudRepository<SessionCredentialMetadataEntity, UUID> {
}
