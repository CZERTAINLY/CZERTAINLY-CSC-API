package com.czertainly.csc.model.csc.requests;

import com.czertainly.csc.model.csc.CertificateReturnType;

import java.util.UUID;

public record CredentialInfoRequest(
        UUID credentialID,
        CertificateReturnType certificateReturnType,
        Boolean returnCertificateInfo,
        Boolean returnAuthInfo
) {

}
