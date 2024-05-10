package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.clients.signserver.SignserverClient;
import com.czertainly.signserver.csc.common.result.ErrorWithDescription;
import com.czertainly.signserver.csc.common.result.Result;
import com.czertainly.signserver.csc.model.SignDocParameters;
import com.czertainly.signserver.csc.model.SignedDocuments;
import com.czertainly.signserver.csc.providers.DistinguishedNameProvider;
import com.czertainly.signserver.csc.signing.configuration.WorkerRepository;
import org.springframework.stereotype.Component;

@Component
public class DocumentSigning {

    SignserverClient signserverClient;
    WorkerRepository workerRepository;
    KeySelector keySelector;
    DistinguishedNameProvider distinguishedNameProvider;


    public DocumentSigning(SignserverClient signserverClient, WorkerRepository workerRepository, PreloadingKeySelector keySelector, DistinguishedNameProvider distinguishedNameProvider) {
        this.signserverClient = signserverClient;
        this.workerRepository = workerRepository;
        this.keySelector = keySelector;
        this.distinguishedNameProvider = distinguishedNameProvider;

    }

    public Result<SignedDocuments, ErrorWithDescription> sign(SignDocParameters parameters) {
        return Result.error(new ErrorWithDescription("Not implemented", "This method is not implemented yet"));

    }

    public void checkSignaturesAuthorizedBySAD(SignedDocuments signedDocuments) {
        // Check if the signatures are authorized by the SAD
    }

}
