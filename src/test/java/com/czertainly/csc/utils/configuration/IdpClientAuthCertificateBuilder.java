package com.czertainly.csc.utils.configuration;

import com.czertainly.csc.configuration.idp.IdpClientAuth;

public class IdpClientAuthCertificateBuilder {

    public static IdpClientAuth.IdpClientAuthCertificate of(String keystoreBundle) {
        return new IdpClientAuth.IdpClientAuthCertificate(keystoreBundle);
    }
}
