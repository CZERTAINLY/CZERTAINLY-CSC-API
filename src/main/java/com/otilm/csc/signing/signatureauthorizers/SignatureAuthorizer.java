package com.otilm.csc.signing.signatureauthorizers;

import com.otilm.csc.api.auth.SignatureActivationData;
import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;

import java.util.List;

public interface SignatureAuthorizer {

    Result<Boolean, TextError> authorize(List<String> documents, SignatureActivationData sad);


}
