package com.czertainly.signserver.csc.api.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;

public class CscAuthenticationToken extends JwtAuthenticationToken {

    SignatureActivationData signatureActivationData;

    public CscAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities, String name,
                                  SignatureActivationData signatureActivationData
    ) {
        super(jwt, authorities, name);
        this.signatureActivationData = signatureActivationData;
    }

    public SignatureActivationData getSignatureActivationData() {
        return signatureActivationData;
    }
}
