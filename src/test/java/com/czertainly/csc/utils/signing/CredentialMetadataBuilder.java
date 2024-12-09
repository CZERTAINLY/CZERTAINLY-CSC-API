package com.czertainly.csc.utils.signing;

import com.czertainly.csc.model.csc.CredentialMetadata;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import java.util.Optional;
import java.util.UUID;

import static org.instancio.Select.field;


public class CredentialMetadataBuilder {

    InstancioClassApi<CredentialMetadata> partial = Instancio.of(CredentialMetadata.class);

    public static CredentialMetadata aCredentialMetadata() {
        return Instancio.of(CredentialMetadata.class)
                        .create();
    }

    public static CredentialMetadataBuilder create() {
        return new CredentialMetadataBuilder();
    }

    public CredentialMetadataBuilder withId(UUID id) {
        partial.set(field(CredentialMetadata::id), id);
        return this;
    }

    public CredentialMetadataBuilder withUserId(String userId) {
        partial.set(field(CredentialMetadata::userId), userId);
        return this;
    }

    public CredentialMetadataBuilder withKeyAlias(String keyAlias) {
        partial.set(field(CredentialMetadata::keyAlias), keyAlias);
        return this;
    }

    public CredentialMetadataBuilder withCredentialProfileName(String credentialProfileName) {
        partial.set(field(CredentialMetadata::credentialProfileName), credentialProfileName);
        return this;
    }

    public CredentialMetadataBuilder withSignatureQualifier(String signatureQualifier) {
        partial.set(field(CredentialMetadata::signatureQualifier), Optional.of(signatureQualifier));
        return this;
    }

    public CredentialMetadataBuilder withMultisign(int multisign) {
        partial.set(field(CredentialMetadata::multisign), multisign);
        return this;
    }

    public CredentialMetadataBuilder withScal(String scal) {
        partial.set(field(CredentialMetadata::scal), Optional.of(scal));
        return this;
    }

    public CredentialMetadataBuilder withCryptoTokenName(String cryptoTokenName) {
        partial.set(field(CredentialMetadata::cryptoTokenName), cryptoTokenName);
        return this;
    }

    public CredentialMetadataBuilder withDisabled(boolean disabled) {
        partial.set(field(CredentialMetadata::disabled), disabled);
        return this;
    }

    public CredentialMetadata build() {
        return partial.create();
    }

}
