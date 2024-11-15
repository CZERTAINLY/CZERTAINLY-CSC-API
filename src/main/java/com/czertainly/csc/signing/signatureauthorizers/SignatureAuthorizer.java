package com.czertainly.csc.signing.signatureauthorizers;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;

import java.util.List;

public interface SignatureAuthorizer {

    Result<Boolean, TextError> authorize(List<String> documents, SignatureActivationData sad);


}
