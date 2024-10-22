package com.czertainly.csc.signing;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.SignDocParameters;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.springframework.stereotype.Component;

@Component
public class DocumentSigning {

    SignserverClient signserverClient;
    WorkerRepository workerRepository;
    KeySelector keySelector;


    public DocumentSigning(SignserverClient signserverClient, WorkerRepository workerRepository, PreloadingKeySelector keySelector) {
        this.signserverClient = signserverClient;
        this.workerRepository = workerRepository;
        this.keySelector = keySelector;
    }

    public Result<SignedDocuments, TextError> sign(SignDocParameters parameters) {
        return Result.error(TextError.of("Not implemented", "This method is not implemented yet"));

    }

    public void checkSignaturesAuthorizedBySAD(SignedDocuments signedDocuments) {
        // Check if the signatures are authorized by the SAD
    }

}
