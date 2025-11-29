package com.czertainly.csc.signing.configuration.process.configuration;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.crypto.SignatureAlgorithm;
import com.czertainly.csc.signing.configuration.DocumentType;

public class PlainHashSignatureProcessConfiguration extends SignatureProcessConfiguration {


    public PlainHashSignatureProcessConfiguration(
            String userID, SignatureActivationData sad,
            SignatureAlgorithm signatureAlgorithm
    ) {
        super(userID, sad, null, null, null,
              null, signatureAlgorithm, false, DocumentType.RAW
        );
    }
}
