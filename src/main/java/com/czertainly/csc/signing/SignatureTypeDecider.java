package com.czertainly.csc.signing;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.SignDocParameters;
import org.springframework.stereotype.Component;

@Component
public class SignatureTypeDecider {

    public Result<SignatureType, TextError> decideType(SignDocParameters parameters) {

        if (parameters.sessionId()
                      .isPresent() && parameters.credentialID() != null && parameters.signatureQualifier() != null) {
            return Result.error(TextError.of(
                    "Session ID, signature qualifier and credential ID must not be present at the same time."));
        }

        if (parameters.sessionId().isPresent()) {
            if (parameters.credentialID() != null) {
                return Result.error(TextError.of("Both session ID and credential ID are present."));
            }

            if (parameters.signatureQualifier() == null || parameters.signatureQualifier().isBlank()) {
                return Result.error(TextError.of("Session ID is present but signature qualifier is missing."));
            }
            return Result.success(SignatureType.SESSION);
        } else if (parameters.signatureQualifier() != null) {
            if (parameters.credentialID() != null) {
                return Result.success(SignatureType.LONG_TERM);
            } else {
                return Result.success(SignatureType.ONE_TIME);
            }
        } else if (parameters.credentialID() != null) {
            return Result.success(SignatureType.LONG_TERM);
        } else {
            return Result.error(
                    TextError.of("Neither session ID nor signature qualifier nor credential ID is present."));
        }
    }
}
