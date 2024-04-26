package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.api.auth.SignatureActivationData;
import com.czertainly.signserver.csc.clients.signserver.SignserverClient;
import com.czertainly.signserver.csc.common.ErrorWithDescription;
import com.czertainly.signserver.csc.common.Result;
import com.czertainly.signserver.csc.model.SignDocParameters;
import com.czertainly.signserver.csc.model.SignedDocuments;
import com.czertainly.signserver.csc.signing.configuration.CapabilitiesFilter;
import com.czertainly.signserver.csc.signing.configuration.ConformanceLevel;
import com.czertainly.signserver.csc.signing.configuration.WorkerRepository;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static com.czertainly.signserver.csc.api.ErrorCodes.INVALID_REQUEST;

@Component
public class DocumentHashSigning {

    WorkerRepository workerRepository;
    KeySelector keySelector;
    DistinguishedNameProvider distinguishedNameProvider;
    SignserverClient signserverClient;

    public DocumentHashSigning(WorkerRepository workerRepository, KeySelector keySelector,
                               DistinguishedNameProvider distinguishedNameProvider, SignserverClient signserverClient
    ) {
        this.workerRepository = workerRepository;
        this.keySelector = keySelector;
        this.distinguishedNameProvider = distinguishedNameProvider;
        this.signserverClient = signserverClient;
    }


    public Result<SignedDocuments, ErrorWithDescription> sign(SignDocParameters parameters) {
        List<String> allHashes = parameters.documentDigestsToSign().stream()
                                           .flatMap(digestsToSign -> digestsToSign.hashes().stream())
                                           .toList();
        if (areSignaturesAuthorizedBySAD(allHashes, parameters.sad())) {

            for (var documentDigestsToSign : parameters.documentDigestsToSign()) {
                var requiredWorkerCapabilities = CapabilitiesFilter.configure()
                                                                   .withSignatureQualifier(
                                                                           parameters.signatureQualifier())
                                                                   .withSignatureFormat(
                                                                           documentDigestsToSign.signatureFormat())
                                                                   .withConformanceLevel(
                                                                           documentDigestsToSign.conformanceLevel())
                                                                   .build();

                var worker = workerRepository.selectWorker(requiredWorkerCapabilities);
                if (worker == null) {
                    return Result.error(
                            new ErrorWithDescription(INVALID_REQUEST, "No suitable signer found for the signature parameters specified."));
                }

                var key = keySelector.selectKey(worker.worker().workerId());
                var dn = distinguishedNameProvider.getDistinguishedName(null);

                signserverClient
                        .generateCSR(key.cryptoTokenId(), key.keyAlias(), dn, "SHA512WithRSA")
                        .doWith(
                                csr -> System.out.println("CSR generated: " + csr.getSubject().toString()),
                                error -> System.out.println("Error while generating CSR: " + error.description())
                        );
            }

            return Result.ok(new SignedDocuments(new ArrayList<>(), null, null, null));

        } else {
            return Result.error(
                    new ErrorWithDescription(INVALID_REQUEST, "Some of documentDigests not authorized by the SAD"));
        }
    }

    public boolean areSignaturesAuthorizedBySAD(List<String> hashes, SignatureActivationData sad) {
        if (sad.getHashes().isPresent()) {
            return sad.getHashes().get().containsAll(hashes);
        }
        return false;
    }

}
