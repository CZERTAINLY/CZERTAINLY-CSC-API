package com.czertainly.csc.utils.signing;

import com.czertainly.csc.model.SignDocParameters;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import java.util.Optional;
import java.util.UUID;

import static org.instancio.Select.field;

public class aSignDocParameters {

    InstancioClassApi<SignDocParameters> partial = Instancio.of(SignDocParameters.class);

    public static aSignDocParameters instance() {
        return new aSignDocParameters();
    }


    public aSignDocParameters withCredentialId(UUID credentialId) {
        partial.set(field(SignDocParameters::credentialID), credentialId);
        return this;
    }

    public aSignDocParameters withSignatureQualifier(String signatureQualifier) {
        partial.set(field(SignDocParameters::signatureQualifier), signatureQualifier);
        return this;
    }

    public aSignDocParameters withSessionId(UUID sessionId) {
        if (sessionId == null) {
            partial.set(field(SignDocParameters::sessionId), Optional.empty());
        } else {
            partial.set(field(SignDocParameters::sessionId), Optional.of(sessionId));
        }
        return this;
    }

    public SignDocParameters build() {
        return partial.create();
    }

}
