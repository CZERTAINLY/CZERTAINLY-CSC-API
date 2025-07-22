package com.czertainly.csc.signing;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.SignDocParameters;
import com.czertainly.csc.model.SignHashParameters;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.model.SignedHashes;
import org.springframework.stereotype.Component;

@Component
public class SignatureFacade {

    DocumentContentSigning documentSigning;
    DocumentHashSigning documentHashSigning;

    public SignatureFacade(DocumentContentSigning documentSigning, DocumentHashSigning documentHashSigning) {
        this.documentSigning = documentSigning;
        this.documentHashSigning = documentHashSigning;
    }

    public Result<SignedDocuments, TextError> signDocuments(
            SignDocParameters signDocParameters, CscAuthenticationToken cscAuthenticationToken
    ) {

        if (!signDocParameters.documentsToSign().isEmpty()) {
            return documentSigning.sign(signDocParameters, cscAuthenticationToken);
        } else if (!signDocParameters.documentDigestsToSign().isEmpty()) {
            return documentHashSigning.sign(signDocParameters, cscAuthenticationToken);
        } else {
            return Result.error(TextError.of("Invalid input", "No documents to sign."));
        }

    }

    public Result<SignedHashes, TextError> signHashes(SignHashParameters signHashParameters) {
        return Result.error(TextError.of("Not implemented", "The method is not yet implemented."));
    }

}
