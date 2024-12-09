package com.czertainly.csc.utils.signing;

import com.czertainly.csc.service.credentials.CredentialSessionStatus;
import com.czertainly.csc.service.credentials.SigningSession;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import java.time.ZonedDateTime;
import java.util.UUID;

import static org.instancio.Select.field;

public class aSigningSession {

    InstancioClassApi<SigningSession> partial = Instancio.of(SigningSession.class);

    public static aSigningSession instance() {
        return new aSigningSession();
    }

    public aSigningSession withId(UUID id) {
        partial.set(field(SigningSession::id), id);
        return this;
    }

    public aSigningSession withCredentialId(UUID credentialId) {
        partial.set(field(SigningSession::credentialId), credentialId);
        return this;
    }

    public aSigningSession withExpiresIn(ZonedDateTime expiresIn) {
        partial.set(field(SigningSession::getExpiresIn), expiresIn);
        return this;
    }

    public aSigningSession withStatus(CredentialSessionStatus status) {
        partial.set(field(SigningSession::status), status);
        return this;
    }

    public SigningSession build() {
        return partial.create();
    }

}
