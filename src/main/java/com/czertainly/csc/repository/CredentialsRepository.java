package com.czertainly.csc.repository;


import com.czertainly.csc.repository.entities.CredentialMetadataEntity;
import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.UUID;


public interface CredentialsRepository extends CrudRepository<CredentialMetadataEntity, UUID> {

    List<CredentialMetadataEntity> findByUserId(String userID);

}
