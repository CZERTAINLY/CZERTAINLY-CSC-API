package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.api.auth.SignatureActivationData;
import com.czertainly.signserver.csc.clients.ejbca.EjbcaClient;
import com.czertainly.signserver.csc.clients.signserver.SignserverClient;
import com.czertainly.signserver.csc.common.ErrorWithDescription;
import com.czertainly.signserver.csc.common.Result;
import com.czertainly.signserver.csc.crypto.NaivePasswordGenerator;
import com.czertainly.signserver.csc.crypto.PasswordGenerator;
import com.czertainly.signserver.csc.model.DocumentDigestsToSign;
import com.czertainly.signserver.csc.model.SignDocParameters;
import com.czertainly.signserver.csc.model.SignedDocuments;
import com.czertainly.signserver.csc.model.ejbca.EndEntity;
import com.czertainly.signserver.csc.signing.configuration.CapabilitiesFilter;
import com.czertainly.signserver.csc.signing.configuration.WorkerRepository;
import com.czertainly.signserver.csc.signing.configuration.WorkerWithCapabilities;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.function.Supplier;

import static com.czertainly.signserver.csc.api.ErrorCodes.INVALID_REQUEST;

@Component
public class DocumentHashSigning {

    private final WorkerRepository workerRepository;
    private final KeySelector keySelector;
    private final DistinguishedNameProvider distinguishedNameProvider;

    private final UserInfoProvider userInfoProvider;
    private final PasswordGenerator passwordGenerator;
    private final SignserverClient signserverClient;
    private final EjbcaClient ejbcaClient;

    public DocumentHashSigning(WorkerRepository workerRepository, KeySelector keySelector,
                               IdpUserInfoProvider userInfoProvider, NaivePasswordGenerator passwordGenerator,
                               DistinguishedNameProvider distinguishedNameProvider, SignserverClient signserverClient,
                               EjbcaClient ejbcaClient
    ) {
        this.workerRepository = workerRepository;
        this.keySelector = keySelector;
        this.userInfoProvider = userInfoProvider;
        this.passwordGenerator = passwordGenerator;
        this.distinguishedNameProvider = distinguishedNameProvider;
        this.signserverClient = signserverClient;
        this.ejbcaClient = ejbcaClient;
    }


    public Result<SignedDocuments, ErrorWithDescription> sign(SignDocParameters parameters, String accessToken) {
        List<String> allHashes = parameters.documentDigestsToSign().stream()
                                           .flatMap(digestsToSign -> digestsToSign.hashes().stream())
                                           .toList();

        return ifAuthorized(
                allHashes, parameters.sad(),
                () -> generateKeyAndSign(parameters, accessToken),
                () -> Result.error(
                        new ErrorWithDescription(INVALID_REQUEST,
                                                 "Some of documentDigests not authorized by the SAD."
                        )
                )
        );
    }

    private Result<SignedDocuments, ErrorWithDescription> generateKeyAndSign(
            SignDocParameters parameters, String accessToken
    ) {
        var signatures = new ArrayList<Signature>();
        var ocsps = new HashSet<String>();
        var crls = new HashSet<String>();
        var certificates = new HashSet<String>();

        for (DocumentDigestsToSign documentDigestsToSign : parameters.documentDigestsToSign()) {
            var worker = getCompatibleWorker(parameters, documentDigestsToSign);

            if (worker != null) {
                var key = keySelector.selectKey(worker.worker().workerId());
                var userInfo = userInfoProvider.getUserInfo(accessToken);
                var dn = distinguishedNameProvider.getDistinguishedName(userInfo);
                var password = passwordGenerator.generate();

                EndEntity endEntity = new EndEntity(userInfo.getAttribute("name", "no name"), password, dn);
                var createEntityResult = ejbcaClient.createEndEntity(endEntity);
                if (createEntityResult.isError()) {
                    return Result.error(createEntityResult.getError());
                }

                var generateCsrResult = signserverClient
                        .generateCSR(key.cryptoTokenId(), key.keyAlias(), dn,
                                     documentDigestsToSign.getSignatureAlgorithm()
                        );
                if (generateCsrResult.isError()) {
                    return Result.error(generateCsrResult.getError());
                }
                byte[] csr = generateCsrResult.getValue();

                var signCsrResult = ejbcaClient.signCertificateRequest(endEntity, csr);
                if (signCsrResult.isError()) {
                    return Result.error(signCsrResult.getError());
                }
                byte[] certificateChain = signCsrResult.getValue();
                var importCertificateChainresponse = signserverClient.importCertificateChain(key.cryptoTokenId(),
                                                                                             key.keyAlias(),
                                                                                             certificateChain
                );
                if (importCertificateChainresponse.isError()) {
                    return Result.error(importCertificateChainresponse.getError());
                }
                if (documentDigestsToSign.hashes().size() == 1) {
                    var signatureResult = signserverClient.signSingleHash(worker.worker().workerName(), documentDigestsToSign.hashes().getFirst().getBytes(), key.keyAlias(), documentDigestsToSign.digestAlgorithm());
                    if (signatureResult.isError()) {
                        return Result.error(signatureResult.getError());
                    } else {
                        signatures.add(signatureResult.getValue());
                    }
                } else {
                    var signatureResult = signserverClient.signMultipleHashes(worker.worker().workerName(), documentDigestsToSign, key.keyAlias());
                    if (signatureResult.isError()) {
                        return Result.error(signatureResult.getError());
                    } else {
                        signatures.addAll(signatureResult.getValue());
                    }
                }


            } else {
                return Result.error(
                        new ErrorWithDescription(INVALID_REQUEST,
                                                 "No suitable signer found for the signature parameters specified."
                        ));
            }

        }
        return Result.ok(new SignedDocuments(signatures, crls, ocsps, certificates));
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
