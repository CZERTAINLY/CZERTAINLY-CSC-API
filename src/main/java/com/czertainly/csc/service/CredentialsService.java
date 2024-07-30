package com.czertainly.csc.service;

import com.czertainly.csc.clients.ejbca.EjbcaClient;
import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.components.CertificateValidityDecider;
import com.czertainly.csc.components.DateConverter;
import com.czertainly.csc.controllers.exceptions.ServerErrorException;
import com.czertainly.csc.crypto.AlgorithmHelper;
import com.czertainly.csc.crypto.CertificateParser;
import com.czertainly.csc.crypto.PasswordGenerator;
import com.czertainly.csc.model.csc.*;
import com.czertainly.csc.model.csc.requests.CreateCredentialRequest;
import com.czertainly.csc.model.csc.requests.CredentialInfoRequest;
import com.czertainly.csc.model.csc.requests.RekeyCredentialRequest;
import com.czertainly.csc.model.ejbca.EndEntity;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.model.signserver.CryptoTokenKey;
import com.czertainly.csc.repository.CredentialsRepository;
import com.czertainly.csc.repository.entities.CredentialMetadataEntity;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

@Service
public class CredentialsService {

    private static final Logger logger = LoggerFactory.getLogger(CredentialsService.class);

    private final PasswordGenerator passwordGenerator;
    private final EjbcaClient ejbcaClient;
    private final SignserverClient signserverClient;
    private final CredentialsRepository credentialsRepository;
    private final WorkerRepository workerRepository;
    private final CertificateParser certificateParser;

    private final AlgorithmHelper algorithmHelper;
    private final DateConverter dateConverter;
    private final CertificateValidityDecider certificateValidityDecider;

    public CredentialsService(PasswordGenerator passwordGenerator, EjbcaClient ejbcaClient,
                              SignserverClient signserverClient, CredentialsRepository credentialsRepository,
                              WorkerRepository workerRepository, CertificateParser certificateParser,
                              AlgorithmHelper algorithmHelper, DateConverter dateConverter,
                              CertificateValidityDecider certificateValidityDecider
    ) {
        this.passwordGenerator = passwordGenerator;
        this.ejbcaClient = ejbcaClient;
        this.signserverClient = signserverClient;
        this.credentialsRepository = credentialsRepository;
        this.workerRepository = workerRepository;
        this.certificateParser = certificateParser;
        this.algorithmHelper = algorithmHelper;
        this.dateConverter = dateConverter;
        this.certificateValidityDecider = certificateValidityDecider;
    }

    public UUID createCredential(CreateCredentialRequest createCredentialRequest) {
        logger.debug("Creating new credential for user '{}'.", createCredentialRequest.userId());
        logger.trace(createCredentialRequest.toString());

        CryptoToken token = getCryptoTokenOrThrow(createCredentialRequest.cryptoTokenName());
        String uniqueUserId = createUniqueUserId(createCredentialRequest.userId());
        String tokenAlias = getUniqueKeyAlias(uniqueUserId);

        String generatedKeyAlias = signserverClient.generateKey(token.id(), tokenAlias,
                                                                createCredentialRequest.keyAlgorithm(),
                                                                createCredentialRequest.keySpecification()
        );
        EndEntity endEntity = createEndEntity(uniqueUserId, createCredentialRequest.dn(),
                                              createCredentialRequest.san()
        );
        byte[] csr = signserverClient.generateCSR(token.id(), generatedKeyAlias, createCredentialRequest.dn(),
                                                  createCredentialRequest.csrSignatureAlgorithm()
        );

        byte[] certificateChain = ejbcaClient.signCertificateRequest(endEntity, csr);
        try {
            Collection<X509CertificateHolder> certificates = certificateParser.parsePkcs7Chain(certificateChain);
            X509CertificateHolder endCertificate = certificates.stream().findFirst().orElseThrow();
            List<byte[]> encodedCertificates = certificates.stream().map(
                    x509CertificateHolder -> {
                        try {
                            return x509CertificateHolder.getEncoded();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }).toList();
            signserverClient.importCertificateChain(token.id(), generatedKeyAlias, encodedCertificates);

            CredentialMetadataEntity savedEntity = saveNewCredential(createCredentialRequest, generatedKeyAlias, token,
                                                                     endEntity, endCertificate
            );
            return savedEntity.getId();
        } catch (CMSException | NoSuchElementException e) {
            throw new ServerErrorException("Failed to create credential for user {}", createCredentialRequest.userId(),
                                           e
            );
        }

    }

    public void deleteCredential(UUID credentialId) {
        logger.debug("Deleting credential with ID '{}'.", credentialId);
        CredentialMetadataEntity credentialMetadata = getCredentialMetadata(credentialId);
        CryptoToken token = workerRepository.getCryptoToken(credentialMetadata.getCryptoTokenName());
        try {
            signserverClient.removeKey(token.id(), credentialMetadata.getKeyAlias());
        } catch (Exception e) {
            logger.warn(
                    "Failed to remove key '{}' belonging to credential '{}' from SignServer. Remove the key manually.",
                    credentialMetadata.getKeyAlias(), credentialId, e
            );
        }
        try {
            credentialsRepository.deleteById(credentialId);
        } catch (Exception e) {
            logger.warn("Failed to remove credential '{}' from database.", credentialId, e);
        }
    }

    public void disableCredential(UUID credentialId) {
        updateCredentialStatus(credentialId, true);
    }

    public void enableCredential(UUID credentialId) {
        updateCredentialStatus(credentialId, false);
    }

    public void rekey(RekeyCredentialRequest request) {
        logger.debug("Renewing certificate for credential '{}'.", request.credentialID());
        CredentialMetadataEntity credentialMetadata = getCredentialMetadata(request.credentialID());
        CryptoToken currentCryptoToken = getCryptoTokenOrThrow(credentialMetadata.getCryptoTokenName());
        CryptoTokenKey currentKey = signserverClient.getCryptoTokenKey(currentCryptoToken.id(),
                                                                       credentialMetadata.getKeyAlias()
        );
        RekeyCredentialRequest mergedRequest = mergerRekeyRequestWithCurrentSettings(request,
                                                                                     credentialMetadata,
                                                                                     currentKey
        );

        CryptoToken newCryptoToken = getCryptoTokenOrThrow(mergedRequest.cryptoTokenName());
        String newKeyAlias = getUniqueKeyAlias(credentialMetadata.getEndEntityName());
        String generatedKeyAlias = signserverClient.generateKey(currentCryptoToken.id(), newKeyAlias,
                                                                mergedRequest.keyAlgorithm(),
                                                                mergedRequest.keySpecification()
        );

        EndEntity endEntity = ejbcaClient.getEndEntity(credentialMetadata.getEndEntityName());

        if (endEntity == null) {
            throw new IllegalArgumentException(
                    String.format("End entity '%s' not found in EJBCA.", credentialMetadata.getEndEntityName())
            );
        }

        byte[] csr = signserverClient.generateCSR(
                newCryptoToken.id(),
                generatedKeyAlias,
                endEntity.subjectDN(),
                mergedRequest.csrSignatureAlgorithm()
        );

        byte[] certificateChain = ejbcaClient.signCertificateRequest(endEntity, csr);
        try {
            Collection<X509CertificateHolder> certificates = certificateParser.parsePkcs7Chain(certificateChain);
            X509CertificateHolder endCertificate = certificates.stream().findFirst().orElseThrow();
            signserverClient.importCertificateChain(newCryptoToken.id(), generatedKeyAlias,
                                                    certificates.stream().map(
                                                            x509CertificateHolder -> {
                                                                try {
                                                                    return x509CertificateHolder.getEncoded();
                                                                } catch (IOException e) {
                                                                    throw new RuntimeException(e);
                                                                }
                                                            }).toList()
            );

            credentialMetadata.setCurrentCertificateSn(endCertificate.getSerialNumber().toString(16));
            credentialMetadata.setCurrentCertificateIssuer(endCertificate.getIssuer().toString());
            credentialMetadata.setKeyAlias(generatedKeyAlias);
            credentialMetadata.setCryptoTokenName(newCryptoToken.name());

            signserverClient.removeKey(currentCryptoToken.id(), currentKey.keyAlias());
        } catch (CMSException | NoSuchElementException e) {
            throw new ServerErrorException("Failed to renew certificate for credential {}",
                                           request.credentialID().toString(), e
            );
        }
    }

    private RekeyCredentialRequest mergerRekeyRequestWithCurrentSettings(RekeyCredentialRequest request,
                                                                         CredentialMetadataEntity credentialMetadata,
                                                                         CryptoTokenKey currentKey
    ) {
        String newCryptoTokenName = credentialMetadata.getCryptoTokenName();
        if (request.cryptoTokenName() != null) {
            credentialMetadata.setCryptoTokenName(request.cryptoTokenName());
        }


        var newKeyAlgorithm = request.keyAlgorithm() == null ? currentKey.keyAlgorithm() : request.keyAlgorithm();
        var newKeySpec = request.keySpecification() == null ? currentKey.keySpecification() : request.keySpecification();
        var newCsrSignatureAlgorithm = request.csrSignatureAlgorithm() == null ? "SHA256WithRSA" : request.csrSignatureAlgorithm();
        return new RekeyCredentialRequest(
                request.credentialID(),
                newCryptoTokenName,
                newKeyAlgorithm,
                newKeySpec,
                newCsrSignatureAlgorithm
        );
    }

    private void updateCredentialStatus(UUID credentialId, boolean disabled) {
        logger.debug("Updating credential '{}', setting disabled={}.", credentialId, disabled);
        CredentialMetadataEntity credentialMetadata = getCredentialMetadata(credentialId);
        credentialMetadata.setDisabled(disabled);
        try {
            credentialsRepository.save(credentialMetadata);
        } catch (Exception e) {
            logger.warn("Failed to update credential '{}'.", credentialId, e);
        }
    }

    public Credential getCredential(CredentialInfoRequest request) {
        CredentialMetadataEntity credentialMetadata = getCredentialMetadata(request.credentialID());
        CryptoToken token = workerRepository.getCryptoToken(credentialMetadata.getCryptoTokenName());
        List<CryptoTokenKey> keys = signserverClient.queryCryptoTokenKeys(token.id(), true, 0, 2,
                                                                          credentialMetadata.getKeyAlias()
        );
        if (keys.isEmpty()) {
            throw new IllegalArgumentException(
                    String.format("Key '%s' belonging to credential '%s' not found in SignServer.",
                                  credentialMetadata.getKeyAlias(), request.credentialID()
                    ));
        } else if (keys.size() > 1) {
            throw new IllegalArgumentException(
                    String.format("Multiple keys '%s' belonging to credential '%s' found in SignServer.",
                                  credentialMetadata.getKeyAlias(), request.credentialID()
                    ));
        }

        CryptoTokenKey key = keys.getFirst();
        String curve = null;
        Integer keyLength = null;
        if (key.keyAlgorithm().equalsIgnoreCase("ECDSA")) {
            curve = key.keySpecification();
        }
        if (key.keyAlgorithm().equalsIgnoreCase("RSA")) {
            keyLength = Integer.parseInt(key.keySpecification());
        }

        X509Certificate endCertificate = certificateParser.parseDerEncodedCertificate(key.chain().getFirst());
        CertificateStatus certificateStatus = certificateValidityDecider.decideStatus(endCertificate);
        KeyStatus keyStatus = credentialMetadata.isDisabled() ? KeyStatus.DISABLED : KeyStatus.ENABLED;
        List<byte[]> certificates = getCertificates(request, key);


        ZoneId utcZone = ZoneId.of("UTC");

        return new Credential(
                credentialMetadata.getId().toString(),
                credentialMetadata.getDescription(),
                credentialMetadata.getSignatureQualifier(),
                new KeyInfo(
                        keyStatus,
                        algorithmHelper.getKeyAlgorithmIdentifier(key.keyAlgorithm()),
                        keyLength,
                        curve
                ),
                new CertificateInfo(
                        certificateStatus,
                        certificates,
                        endCertificate.getSerialNumber().toString(16),
                        endCertificate.getIssuerX500Principal().getName(),
                        endCertificate.getSubjectX500Principal().getName(),
                        dateConverter.dateToZonedDateTime(endCertificate.getNotBefore(), utcZone),
                        dateConverter.dateToZonedDateTime(endCertificate.getNotAfter(), utcZone)
                ),
                credentialMetadata.getMultisign()
        );

    }

    private List<byte[]> getCertificates(CredentialInfoRequest request, CryptoTokenKey key) {
        return switch (request.certificateReturnType()) {
            case CERTIFICATE_CHAIN -> key.chain();
            case END_CERTIFICATE -> List.of(key.chain().getFirst());
            case NONE -> List.of();
        };
    }


    private CredentialMetadataEntity getCredentialMetadata(UUID credentialId) {
        return credentialsRepository
                .findById(credentialId)
                .orElseThrow(
                        () -> new IllegalArgumentException(
                                String.format(
                                        "Credential with ID '%s' not found.",
                                        credentialId
                                )
                        ));
    }

    private EndEntity createEndEntity(String userId, String dn, String san) {
        logger.debug("Creating new end entity for user '{}'", userId);
        var password = passwordGenerator.generate();
        EndEntity endEntity = new EndEntity(userId, password, dn, san);
        ejbcaClient.createEndEntity(endEntity);
        return endEntity;
    }

    private String createUniqueUserId(String userID) {
        String random_id = RandomStringUtils.random(8, true, true);
        String uniqueUserId = String.format("%s-%s", userID, random_id);
        logger.trace("A new unique user ID '{}' was generated.", uniqueUserId);
        return uniqueUserId;
    }

    private String getUniqueKeyAlias(String userId) {
        String random_id = RandomStringUtils.random(8, true, true);
        return String.format("%s-%s", userId, random_id);
    }

    private CryptoToken getCryptoTokenOrThrow(String cryptoTokenName) {
        CryptoToken token = workerRepository.getCryptoToken(cryptoTokenName);
        if (token == null) {
            throw new IllegalArgumentException(String.format("Crypto token '%s' not found.", cryptoTokenName));
        }
        return token;
    }

    private CredentialMetadataEntity saveNewCredential(CreateCredentialRequest createCredentialRequest,
                                                       String generatedKeyAlias,
                                                       CryptoToken cryptoToken, EndEntity endEntity,
                                                       X509CertificateHolder endCertificate
    ) {
        CredentialMetadataEntity credentialMetadata = new CredentialMetadataEntity();
        credentialMetadata.setId(UUID.randomUUID());
        credentialMetadata.setUserId(createCredentialRequest.userId());
        credentialMetadata.setKeyAlias(generatedKeyAlias);
        credentialMetadata.setCryptoTokenName(cryptoToken.name());
        credentialMetadata.setEndEntityName(endEntity.username());
        credentialMetadata.setCurrentCertificateSn(endCertificate.getSerialNumber().toString(16));
        credentialMetadata.setCurrentCertificateIssuer(endCertificate.getIssuer().toString());
        credentialMetadata.setSignatureQualifier(createCredentialRequest.signatureQualifier());
        credentialMetadata.setMultisign(createCredentialRequest.numberOfSignaturesPerAuthorization());
        credentialMetadata.setScal(createCredentialRequest.scal());
        credentialMetadata.setDescription(createCredentialRequest.description());
        credentialMetadata.setDisabled(false);

        return credentialsRepository.save(credentialMetadata);
    }
}
