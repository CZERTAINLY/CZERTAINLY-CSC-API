package com.czertainly.csc.utils.signing;

import com.czertainly.csc.model.csc.SessionCredentialMetadata;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import java.util.UUID;

import static org.instancio.Select.field;

public class SessionCredentialMetadataBuilder {

    InstancioClassApi<SessionCredentialMetadata> partial = Instancio.of(SessionCredentialMetadata.class);

    public static SessionCredentialMetadata aSessionCredentialMetadata() {
        return Instancio.of(SessionCredentialMetadata.class)
                        .create();
    }

    public static SessionCredentialMetadataBuilder create() {
        return new SessionCredentialMetadataBuilder();
    }

    public SessionCredentialMetadataBuilder withId(UUID id) {
        partial.set(field(SessionCredentialMetadata::id), id);
        return this;
    }

    public SessionCredentialMetadataBuilder withKeyAlias(String keyAlias) {
        partial.set(field(SessionCredentialMetadata::keyAlias), keyAlias);
        return this;
    }

    public SessionCredentialMetadataBuilder withKeyId(UUID keyId) {
        partial.set(field(SessionCredentialMetadata::keyId), keyId);
        return this;
    }

    public SessionCredentialMetadataBuilder withEndEntityName(String endEntityName) {
        partial.set(field(SessionCredentialMetadata::endEntityName), endEntityName);
        return this;
    }

    public SessionCredentialMetadataBuilder withMultisign(int multisign) {
        partial.set(field(SessionCredentialMetadata::multisign), multisign);
        return this;
    }

    public SessionCredentialMetadata build() {
        return partial.create();
    }

}
