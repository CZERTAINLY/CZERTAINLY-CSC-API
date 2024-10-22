package com.czertainly.csc.signing;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.clients.ejbca.EjbcaClient;
import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.crypto.NaivePasswordGenerator;
import com.czertainly.csc.crypto.PasswordGenerator;
import com.czertainly.csc.model.DocumentDigestsToSign;
import com.czertainly.csc.model.SignDocParameters;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.model.csc.CredentialMetadata;
import com.czertainly.csc.model.ejbca.EndEntity;
import com.czertainly.csc.providers.KeyValueSource;
import com.czertainly.csc.service.credentials.CredentialsService;
import com.czertainly.csc.signing.configuration.CapabilitiesFilter;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.profiles.CredentialProfileRepository;
import com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile.SignatureQualifierProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

@Component
public class DocumentHashSigning {

    private final static Logger logger = LoggerFactory.getLogger(DocumentHashSigning.class);
    private final WorkerRepository workerRepository;
    private final KeySelector keySelector;
    private final CredentialProfileRepository credentialProfileRepository;
    private final UserInfoProvider userInfoProvider;
    private final PasswordGenerator passwordGenerator;
    private final SignserverClient signserverClient;
    private final EjbcaClient ejbcaClient;
    private final CredentialsService credentialsService;

    public DocumentHashSigning(WorkerRepository workerRepository, KeySelector keySelector,
                               IdpUserInfoProvider userInfoProvider, NaivePasswordGenerator passwordGenerator,
                               CredentialProfileRepository credentialProfileRepository,
                               SignserverClient signserverClient, EjbcaClient ejbcaClient,
                               CredentialsService credentialsService
    ) {
        this.workerRepository = workerRepository;
        this.keySelector = keySelector;
        this.userInfoProvider = userInfoProvider;
        this.passwordGenerator = passwordGenerator;
        this.credentialProfileRepository = credentialProfileRepository;
        this.signserverClient = signserverClient;
        this.ejbcaClient = ejbcaClient;
        this.credentialsService = credentialsService;
    }


    public Result<SignedDocuments, TextError> sign(
            SignDocParameters parameters, CscAuthenticationToken cscAuthenticationToken
    ) {
        List<String> allHashes = parameters.documentDigestsToSign().stream()
                                           .flatMap(digestsToSign -> digestsToSign.hashes().stream())
                                           .toList();

        return ifAuthorized(
                allHashes, parameters.sad(),
                () ->
                        parameters.credentialID() == null
                                ? generateKeyAndSign(parameters, cscAuthenticationToken)
                                : loadKeyAndSign(parameters, cscAuthenticationToken),
                () -> Result.error(TextError.of("Some signatures of document digests were not authorized by the SAD."))
        );
    }

    private Result<SignedDocuments, TextError> loadKeyAndSign(
            SignDocParameters parameters, CscAuthenticationToken cscAuthenticationToken
    ) {

        var getCredentialresult = credentialsService.getCredentialMetadata(parameters.credentialID(),
                                                                           parameters.userID()
                                                    )
                                                    .mapError(err -> err.extend(
                                                            "Failed to load credential '%s'",
                                                            parameters.credentialID()
                                                    ));
        if (getCredentialresult instanceof Error(var err)) return Result.error(err);
        CredentialMetadata credential = getCredentialresult.unwrap();

        var allSignatures = new ArrayList<Signature>();
        var ocsps = new HashSet<String>();
        var crls = new HashSet<String>();
        var certificates = new HashSet<String>();

        for (DocumentDigestsToSign documentDigestsToSign : parameters.documentDigestsToSign()) {
            if (credential.signatureQualifier().isPresent()) {
                String signatureQualifier = credential.signatureQualifier().orElseThrow();
                if (!signatureQualifier.equals(parameters.signatureQualifier())) {
                    return Result.error(TextError.of(
                            "The signature qualifier '%s' of the requested credential '%s' does not match requested signature qualifier '%s' from the request.",
                            signatureQualifier, credential.id(),
                            parameters.signatureQualifier()
                    ));
                }
            }
            var worker = getCompatibleWorker(parameters, documentDigestsToSign);
            try {
                signHashes(parameters, documentDigestsToSign, worker, credential.keyAlias(), allSignatures, crls, ocsps,
                           certificates
                );
            } catch (Exception e) {
                logger.debug("An error occurred during the signing process with credential %s.", e);
                return Result.error(
                        TextError.of("An error occurred during the signing process with credential %s. %s",
                                     credential.id(), e.getMessage()
                        ));
            }
        }

        return Result.success(new SignedDocuments(allSignatures, crls, ocsps, certificates));
    }

    private Result<SignedDocuments, TextError> generateKeyAndSign(
            SignDocParameters parameters, CscAuthenticationToken cscAuthenticationToken
    ) {
        var allSignatures = new ArrayList<Signature>();
        var ocsps = new HashSet<String>();
        var crls = new HashSet<String>();
        var certificates = new HashSet<String>();

        for (DocumentDigestsToSign documentDigestsToSign : parameters.documentDigestsToSign()) {
            var worker = getCompatibleWorker(parameters, documentDigestsToSign);

            if (worker != null) {
                var key = keySelector.selectKey(worker.worker().workerId());
                try {
                    String accessToken = cscAuthenticationToken.getToken().getTokenValue();
                    var userInfo = userInfoProvider.getUserInfo(accessToken);
                    var keyValueSource = new KeyValueSource(
                            key.keyAlias(), userInfo, cscAuthenticationToken, parameters.sad()
                    );

                    Result<SignatureQualifierProfile, TextError> getProfileResult = credentialProfileRepository
                            .getSignatureQualifierProfile(parameters.signatureQualifier());

                    if (getProfileResult instanceof Error(var err)) return Result.error(err);
                    SignatureQualifierProfile signatureQualifierProfile = getProfileResult.unwrap();

                    Map<String, String> keyValuePairs = keyValueSource.get();
                    var dn = signatureQualifierProfile.getDistinguishedNameProvider()
                                                      .getDistinguishedName(() -> keyValuePairs);
                    var san = signatureQualifierProfile.getSubjectAlternativeNameProvider().getSan(() -> keyValuePairs);
                    var username = signatureQualifierProfile.getUsernameProvider().getUsername(() -> keyValuePairs);
                    var password = passwordGenerator.generate();

                    EndEntity endEntity = new EndEntity(username, password, dn, san);
                    ejbcaClient.createEndEntity(endEntity, signatureQualifierProfile);
                    var result = signserverClient.generateCSR(
                                            key.cryptoTokenId(), key.keyAlias(), dn,
                                            documentDigestsToSign.getSignatureAlgorithm()
                                    )
                                                 .flatMap(csr -> ejbcaClient.signCertificateRequest(endEntity,
                                                                                                    signatureQualifierProfile,
                                                                                                    csr
                                                 ))
                                    .flatMap(certificateChain -> signserverClient.importCertificateChain(
                                            key.cryptoTokenId(), key.keyAlias(), List.of(certificateChain)
                                    ));
                    if (result instanceof Error(var err)) {
                        return Result.error(err);
                    }

                    signHashes(parameters, documentDigestsToSign, worker, key.keyAlias(), allSignatures, crls, ocsps,
                               certificates
                    );
                } catch (Exception e) {
                    logger.info("An error occurred during the signing process. Pre-generated {} key will be removed.",
                                key.keyAlias(), e
                    );
                    throw e;
                } finally {
                    try {
                        signserverClient.removeKey(key.cryptoTokenId(), key.keyAlias());
                        keySelector.markKeyAsUsed(key);
                    } catch (Exception ex) {
                        logger.error("Key {} was not removed and may be in inconsistent state!", key.keyAlias(), ex);
                    }
                }
            } else {
                return Result.error(TextError.of("No suitable signer found for the signature parameters specified."));
            }

        }
        return Result.success(new SignedDocuments(allSignatures, crls, ocsps, certificates));
    }

    private void signHashes(SignDocParameters parameters, DocumentDigestsToSign documentDigestsToSign,
                            WorkerWithCapabilities worker, String keyAlias, ArrayList<Signature> allSignatures,
                            HashSet<String> crls, HashSet<String> ocsps, HashSet<String> certificates
    ) {
        if (documentDigestsToSign.hashes().size() == 1) {
            if (parameters.returnValidationInfo()) {
                signSingleHashWithValidationInfo(documentDigestsToSign, worker, keyAlias, allSignatures, crls, ocsps,
                                                 certificates
                );
            } else {
                signSingleHash(documentDigestsToSign, worker, keyAlias, allSignatures);
            }
        } else {
            if (parameters.returnValidationInfo()) {
                signMultipleHashesWithValidationInfo(documentDigestsToSign, worker, keyAlias, allSignatures, crls,
                                                     ocsps,
                                                     certificates
                );
            } else {
                signMultipleHashes(documentDigestsToSign, worker, keyAlias, allSignatures);
            }
        }
    }

    private void signSingleHash(DocumentDigestsToSign documentDigestsToSign, WorkerWithCapabilities worker,
                                String keyAlias, ArrayList<Signature> allSignatures
    ) {
        Signature signature = signserverClient.signSingleHash(
                worker.worker().workerName(),
                documentDigestsToSign.hashes().getFirst().getBytes(),
                keyAlias,
                documentDigestsToSign.digestAlgorithm()
        );
        allSignatures.add(signature);
    }

    private void signMultipleHashes(DocumentDigestsToSign documentDigestsToSign, WorkerWithCapabilities worker,
                                    String keyAlias, ArrayList<Signature> allSignatures
    ) {
        List<Signature> signatures = signserverClient.signMultipleHashes(
                worker.worker().workerName(),
                documentDigestsToSign,
                keyAlias
        );
        allSignatures.addAll(signatures);
    }

    private void signMultipleHashesWithValidationInfo(DocumentDigestsToSign documentDigestsToSign,
                                                      WorkerWithCapabilities worker,
                                                      String keyAlias, ArrayList<Signature> allSignatures,
                                                      HashSet<String> crls,
                                                      HashSet<String> ocsps, HashSet<String> certificates
    ) {
        SignedDocuments documents = signserverClient.signMultipleHashesWithValidationData(
                worker.worker().workerName(),
                documentDigestsToSign,
                keyAlias
        );
        allSignatures.addAll(documents.signatures());
        crls.addAll(documents.crls());
        ocsps.addAll(documents.ocsps());
        certificates.addAll(documents.certs());
    }

    private void signSingleHashWithValidationInfo(DocumentDigestsToSign documentDigestsToSign,
                                                  WorkerWithCapabilities worker,
                                                  String keyAlias, ArrayList<Signature> allSignatures,
                                                  HashSet<String> crls,
                                                  HashSet<String> ocsps, HashSet<String> certificates
    ) {
        SignedDocuments documents = signserverClient.signSingleHashWithValidationData(
                worker.worker().workerName(),
                documentDigestsToSign.hashes().getFirst().getBytes(),
                keyAlias,
                documentDigestsToSign.digestAlgorithm()
        );
        allSignatures.addAll(documents.signatures());
        crls.addAll(documents.crls());
        ocsps.addAll(documents.ocsps());
        certificates.addAll(documents.certs());
    }

    private WorkerWithCapabilities getCompatibleWorker(
            SignDocParameters parameters,
            DocumentDigestsToSign documentDigestsToSign
    ) {
        var requiredWorkerCapabilities = CapabilitiesFilter
                .configure()
                .withSignatureQualifier(parameters.signatureQualifier())
                .withSignatureFormat(documentDigestsToSign.signatureFormat())
                .withConformanceLevel(documentDigestsToSign.conformanceLevel())
                .withSignatureAlgorithm(documentDigestsToSign.getSignatureAlgorithm())
                .withSignaturePackaging(documentDigestsToSign.signaturePackaging())
                .withReturnValidationInfo(parameters.returnValidationInfo())
                .build();

        return workerRepository.selectWorker(requiredWorkerCapabilities);
    }

    public Result<SignedDocuments, TextError> ifAuthorized(
            List<String> hashes,
            SignatureActivationData sad,
            Supplier<Result<SignedDocuments, TextError>> authorized,
            Supplier<Result<SignedDocuments, TextError>> unauthorized
    ) {
        if (sad.getHashes().isPresent() && sad.getHashes().get().containsAll(hashes)) {
            return authorized.get();
        }
        return unauthorized.get();
    }

}
