package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.api.ErrorCode;
import com.czertainly.signserver.csc.api.auth.SignatureActivationData;
import com.czertainly.signserver.csc.clients.ejbca.EjbcaClient;
import com.czertainly.signserver.csc.clients.signserver.SignserverClient;
import com.czertainly.signserver.csc.common.result.ErrorWithDescription;
import com.czertainly.signserver.csc.common.result.Result;
import com.czertainly.signserver.csc.crypto.NaivePasswordGenerator;
import com.czertainly.signserver.csc.crypto.PasswordGenerator;
import com.czertainly.signserver.csc.model.DocumentDigestsToSign;
import com.czertainly.signserver.csc.model.SignDocParameters;
import com.czertainly.signserver.csc.model.SignedDocuments;
import com.czertainly.signserver.csc.model.ejbca.EndEntity;
import com.czertainly.signserver.csc.providers.DistinguishedNameProvider;
import com.czertainly.signserver.csc.providers.PatternUsernameProvider;
import com.czertainly.signserver.csc.providers.SubjectAlternativeNameProvider;
import com.czertainly.signserver.csc.signing.configuration.CapabilitiesFilter;
import com.czertainly.signserver.csc.signing.configuration.WorkerRepository;
import com.czertainly.signserver.csc.signing.configuration.WorkerWithCapabilities;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.function.Supplier;

@Component
public class DocumentHashSigning {

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


    public Result<SignedDocuments, ErrorWithDescription> sign(SignDocParameters parameters, String accessToken) {
        List<String> allHashes = parameters.documentDigestsToSign().stream()
                                           .flatMap(digestsToSign -> digestsToSign.hashes().stream())
                                           .toList();

        return ifAuthorized(
                allHashes, parameters.sad(),
                () -> generateKeyAndSign(parameters, accessToken),
                () -> Result.error(
                        new ErrorWithDescription(ErrorCode.INVALID_REQUEST.toString(),
                                                 "Some of documentDigests not authorized by the SAD."
                        )
                )
        );
    }

    private Result<SignedDocuments, ErrorWithDescription> generateKeyAndSign(
            SignDocParameters parameters, String accessToken
    ) {
        var allSignatures = new ArrayList<Signature>();
        var ocsps = new HashSet<String>();
        var crls = new HashSet<String>();
        var certificates = new HashSet<String>();

        for (DocumentDigestsToSign documentDigestsToSign : parameters.documentDigestsToSign()) {
            var worker = getCompatibleWorker(parameters, documentDigestsToSign);

            if (worker != null) {
                var key = keySelector.selectKey(worker.worker().workerId());
                var userInfo = userInfoProvider.getUserInfo(accessToken);
                var dn = distinguishedNameProvider.getDistinguishedName(userInfo::getAttributes);
                var san = subjectAlternativeNameProvider.getSan(userInfo::getAttributes);
                var username = patternUsernameProvider.getUsername(userInfo::getAttributes);
                var password = passwordGenerator.generate();

                EndEntity endEntity = new EndEntity(username, password, dn, san);
                ejbcaClient.createEndEntity(endEntity);
                byte[] csr = signserverClient.generateCSR(
                        key.cryptoTokenId(), key.keyAlias(), dn, documentDigestsToSign.getSignatureAlgorithm()
                );

                byte[] certificateChain = ejbcaClient.signCertificateRequest(endEntity, csr);
                signserverClient.importCertificateChain(key.cryptoTokenId(), key.keyAlias(), certificateChain);

                if (documentDigestsToSign.hashes().size() == 1) {
                    Signature signature = signserverClient.signSingleHash(
                            worker.worker().workerName(),
                            documentDigestsToSign.hashes().getFirst().getBytes(),
                            key.keyAlias(),
                            documentDigestsToSign.digestAlgorithm()
                    );
                    allSignatures.add(signature);
                } else {
                    List<Signature> signatures = signserverClient.signMultipleHashes(
                            worker.worker().workerName(),
                            documentDigestsToSign,
                            key.keyAlias()
                    );
                    allSignatures.addAll(signatures);
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
