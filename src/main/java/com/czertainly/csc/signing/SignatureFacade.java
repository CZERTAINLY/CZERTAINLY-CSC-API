package com.czertainly.csc.signing;

import com.czertainly.csc.common.result.ErrorWithDescription;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.model.SignDocParameters;
import com.czertainly.csc.model.SignHashParameters;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.model.SignedHashes;
import org.springframework.stereotype.Component;

@Component
public class SignatureFacade {

    DocumentSigning documentSigning;
    DocumentHashSigning documentHashSigning;

    public SignatureFacade(DocumentSigning documentSigning, DocumentHashSigning documentHashSigning) {
        this.documentSigning = documentSigning;
        this.documentHashSigning = documentHashSigning;
    }

    public Result<SignedDocuments, ErrorWithDescription> signDocuments(SignDocParameters signDocParameters, String accessToken) {

        if (!signDocParameters.documentsToSign().isEmpty()) {
            return documentSigning.sign(signDocParameters);
        } else if (!signDocParameters.documentDigestsToSign().isEmpty()) {
            return documentHashSigning.sign(signDocParameters, accessToken);
        } else {
            return Result.error(new ErrorWithDescription("Invalid input", "No documents to sign."));
        }

    }

    public Result<SignedHashes, ErrorWithDescription> signHashes(SignHashParameters signHashParameters) {
        return Result.error(new ErrorWithDescription("Not implemented", "The method is not yet implemented."));
    }

}
