package com.czertainly.csc.signing;

import com.czertainly.csc.api.ErrorCode;
import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.clients.ejbca.EjbcaClient;
import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.ErrorWithDescription;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.crypto.NaivePasswordGenerator;
import com.czertainly.csc.crypto.PasswordGenerator;
import com.czertainly.csc.model.DocumentDigestsToSign;
import com.czertainly.csc.model.SignDocParameters;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.model.ejbca.EndEntity;
import com.czertainly.csc.model.signserver.CryptoTokenKey;
import com.czertainly.csc.providers.DistinguishedNameProvider;
import com.czertainly.csc.providers.KeyValueSource;
import com.czertainly.csc.providers.PatternUsernameProvider;
import com.czertainly.csc.providers.SubjectAlternativeNameProvider;
import com.czertainly.csc.signing.configuration.CapabilitiesFilter;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.function.Supplier;

@Component
public class DocumentHashSigning {


    private final static Logger logger = LoggerFactory.getLogger(DocumentHashSigning.class);
    private final WorkerRepository workerRepository;
    private final KeySelector keySelector;
    private final DistinguishedNameProvider distinguishedNameProvider;
    private final PatternUsernameProvider patternUsernameProvider;
    private final SubjectAlternativeNameProvider subjectAlternativeNameProvider;
    private final UserInfoProvider userInfoProvider;
    private final PasswordGenerator passwordGenerator;
    private final SignserverClient signserverClient;
    private final EjbcaClient ejbcaClient;

    public DocumentHashSigning(WorkerRepository workerRepository, KeySelector keySelector,
                               IdpUserInfoProvider userInfoProvider, NaivePasswordGenerator passwordGenerator,
                               DistinguishedNameProvider distinguishedNameProvider,
                               PatternUsernameProvider patternUsernameProvider,
                               SubjectAlternativeNameProvider subjectAlternativeNameProvider,
                               SignserverClient signserverClient, EjbcaClient ejbcaClient
    ) {
        this.workerRepository = workerRepository;
        this.keySelector = keySelector;
        this.userInfoProvider = userInfoProvider;
        this.passwordGenerator = passwordGenerator;
        this.distinguishedNameProvider = distinguishedNameProvider;
        this.patternUsernameProvider = patternUsernameProvider;
        this.subjectAlternativeNameProvider = subjectAlternativeNameProvider;
        this.signserverClient = signserverClient;
        this.ejbcaClient = ejbcaClient;
    }


    public Result<SignedDocuments, ErrorWithDescription> sign(
            SignDocParameters parameters, CscAuthenticationToken cscAuthenticationToken
    ) {
        List<String> allHashes = parameters.documentDigestsToSign().stream()
                                           .flatMap(digestsToSign -> digestsToSign.hashes().stream())
                                           .toList();

        return ifAuthorized(
                allHashes, parameters.sad(),
                () -> generateKeyAndSign(parameters, cscAuthenticationToken),
                () -> Result.error(
                        new ErrorWithDescription(ErrorCode.INVALID_REQUEST.toString(),
                                                 "Some of documentDigests not authorized by the SAD."
                        )
                )
        );
    }

    private Result<SignedDocuments, ErrorWithDescription> generateKeyAndSign(
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
                    var dn = distinguishedNameProvider.getDistinguishedName(keyValueSource::get);
                    var san = subjectAlternativeNameProvider.getSan(keyValueSource::get);
                    var username = patternUsernameProvider.getUsername(keyValueSource::get);
                    var password = passwordGenerator.generate();

                    EndEntity endEntity = new EndEntity(username, password, dn, san);
                    ejbcaClient.createEndEntity(endEntity);
                    byte[] csr = signserverClient.generateCSR(
                            key.cryptoTokenId(), key.keyAlias(), dn, documentDigestsToSign.getSignatureAlgorithm()
                    );

                    byte[] certificateChain = ejbcaClient.signCertificateRequest(endEntity, csr);
                    signserverClient.importCertificateChain(key.cryptoTokenId(), key.keyAlias(), certificateChain);

                    signHashes(parameters, documentDigestsToSign, worker, key, allSignatures, crls, ocsps,
                               certificates
                    );
                } catch (Exception e) {
                    logger.info(
                            "An error occurred during the signing process. Pre-generated "
                                    + key.keyAlias() + " key will be removed.", e
                    );
                    throw e;
                } finally {
                    try {
                        keySelector.markKeyAsUsed(key);
                        signserverClient.removeKey(key.cryptoTokenId(), key.keyAlias());
                    } catch (Exception ex) {
                        logger.error("Key " + key.keyAlias() + " was not removed and may be in inconsistent state!",
                                     ex
                        );
                    }
                }
            } else {
                return Result.error(
                        new ErrorWithDescription(ErrorCode.INVALID_REQUEST.toString(),
                                                 "No suitable signer found for the signature parameters specified."
                        ));
            }

        }
        return Result.ok(new SignedDocuments(allSignatures, crls, ocsps, certificates));
    }

    private void signHashes(SignDocParameters parameters, DocumentDigestsToSign documentDigestsToSign,
                            WorkerWithCapabilities worker, CryptoTokenKey key, ArrayList<Signature> allSignatures,
                            HashSet<String> crls, HashSet<String> ocsps, HashSet<String> certificates
    ) {
        if (documentDigestsToSign.hashes().size() == 1) {
            if (parameters.returnValidationInfo()) {
                signSingleHashWithValidationInfo(documentDigestsToSign, worker, key, allSignatures, crls, ocsps,
                                                 certificates
                );
            } else {
                signSingleHash(documentDigestsToSign, worker, key, allSignatures);
            }
        } else {
            if (parameters.returnValidationInfo()) {
                signMultipleHashesWithValidationInfo(documentDigestsToSign, worker, key, allSignatures, crls, ocsps,
                                                     certificates
                );
            } else {
                signMultipleHashes(documentDigestsToSign, worker, key, allSignatures);
            }
        }
    }

    private void signSingleHash(DocumentDigestsToSign documentDigestsToSign, WorkerWithCapabilities worker,
                                CryptoTokenKey key, ArrayList<Signature> allSignatures
    ) {
        Signature signature = signserverClient.signSingleHash(
                worker.worker().workerName(),
                documentDigestsToSign.hashes().getFirst().getBytes(),
                key.keyAlias(),
                documentDigestsToSign.digestAlgorithm()
        );
        allSignatures.add(signature);
    }

    private void signMultipleHashes(DocumentDigestsToSign documentDigestsToSign, WorkerWithCapabilities worker,
                                    CryptoTokenKey key, ArrayList<Signature> allSignatures
    ) {
        List<Signature> signatures = signserverClient.signMultipleHashes(
                worker.worker().workerName(),
                documentDigestsToSign,
                key.keyAlias()
        );
        allSignatures.addAll(signatures);
    }

    private void signMultipleHashesWithValidationInfo(DocumentDigestsToSign documentDigestsToSign,
                                                      WorkerWithCapabilities worker,
                                                      CryptoTokenKey key, ArrayList<Signature> allSignatures,
                                                      HashSet<String> crls,
                                                      HashSet<String> ocsps, HashSet<String> certificates
    ) {
        SignedDocuments documents = signserverClient.signMultipleHashesWithValidationData(
                worker.worker().workerName(),
                documentDigestsToSign,
                key.keyAlias()
        );
        allSignatures.addAll(documents.signatures());
        crls.addAll(documents.crls());
        ocsps.addAll(documents.ocsps());
        certificates.addAll(documents.certs());
    }

    private void signSingleHashWithValidationInfo(DocumentDigestsToSign documentDigestsToSign,
                                                  WorkerWithCapabilities worker,
                                                  CryptoTokenKey key, ArrayList<Signature> allSignatures,
                                                  HashSet<String> crls,
                                                  HashSet<String> ocsps, HashSet<String> certificates
    ) {
        SignedDocuments documents = signserverClient.signSingleHashWithValidationData(
                worker.worker().workerName(),
                documentDigestsToSign.hashes().getFirst().getBytes(),
                key.keyAlias(),
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

    public Result<SignedDocuments, ErrorWithDescription> ifAuthorized(
            List<String> hashes,
            SignatureActivationData sad,
            Supplier<Result<SignedDocuments, ErrorWithDescription>> authorized,
            Supplier<Result<SignedDocuments, ErrorWithDescription>> unauthorized
    ) {
        if (sad.getHashes().isPresent() && sad.getHashes().get().containsAll(hashes)) {
            return authorized.get();
        }
        return unauthorized.get();
    }

}
