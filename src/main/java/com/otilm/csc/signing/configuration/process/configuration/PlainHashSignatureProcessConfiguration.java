package com.otilm.csc.signing.configuration.process.configuration;

import com.otilm.csc.api.auth.SignatureActivationData;
import com.otilm.csc.crypto.SignatureAlgorithm;
import com.otilm.csc.signing.configuration.DocumentType;

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
