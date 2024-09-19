package com.czertainly.csc.repository;


import com.czertainly.csc.repository.entities.CredentialMetadataEntity;
import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;


public interface CredentialsRepository extends CrudRepository<CredentialMetadataEntity, UUID> {

    List<CredentialMetadataEntity> findByUserId(String userID);

    Optional<CredentialMetadataEntity> findByIdAndUserId(UUID credentialID, String userID);

}
