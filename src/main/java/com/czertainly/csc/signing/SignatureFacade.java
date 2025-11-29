package com.czertainly.csc.signing;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.*;
import org.springframework.stereotype.Component;

@Component
public class SignatureFacade {

    private final DocumentContentSigning documentSigning;
    private final DocumentHashSigning documentHashSigning;
    private final PlainHashSigning plainHashSigning;

    public SignatureFacade(DocumentContentSigning documentSigning, DocumentHashSigning documentHashSigning,
                           PlainHashSigning plainHashSigning
    ) {
        this.documentSigning = documentSigning;
        this.documentHashSigning = documentHashSigning;
        this.plainHashSigning = plainHashSigning;
    }

    public Result<SignaturesContainer<DocumentSignature>, TextError> signDocuments(
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

    public Result<SignaturesContainer<PlainSignature>, TextError> signHashes(SignHashParameters signHashParameters) {
        if (signHashParameters.hashes().isEmpty()) {
            return Result.error(TextError.of("No hashes to sign."));
        }
        return plainHashSigning.sign(signHashParameters);
    }

}
