package com.czertainly.csc.utils.configuration;

import com.czertainly.csc.configuration.idp.IdpAuthentication;
import com.czertainly.csc.configuration.idp.IdpClientAuth;
import org.instancio.Instancio;
import org.instancio.InstancioClassApi;

import static org.instancio.Select.field;

public class IdpClientAuthBuilder {

    InstancioClassApi<IdpClientAuth> partial = Instancio.of(IdpClientAuth.class);

    public static IdpClientAuth anIdpClientAuth() {
        return Instancio.of(IdpClientAuth.class)
                        .create();
    }

    public static IdpClientAuthBuilder create() {
        return new IdpClientAuthBuilder();
    }

    public IdpClientAuthBuilder withAuthType(IdpAuthentication authType) {
        partial.set(field(IdpClientAuth::authType), authType);
        return this;
    }

    public IdpClientAuthBuilder withCertificate(IdpClientAuth.IdpClientAuthCertificate certificate) {
        partial.set(field(IdpClientAuth::certificate), certificate);
        return this;
    }

    public IdpClientAuth build() {
        return partial.create();
    }

}
