package com.otilm.csc.utils.configuration;

import com.otilm.csc.configuration.idp.IdpClientAuth;

public class IdpClientAuthCertificateBuilder {

    public static IdpClientAuth.IdpClientAuthCertificate of(String keystoreBundle) {
        return new IdpClientAuth.IdpClientAuthCertificate(keystoreBundle);
    }
}
