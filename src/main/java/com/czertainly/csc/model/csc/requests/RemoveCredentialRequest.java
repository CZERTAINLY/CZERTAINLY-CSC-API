package com.czertainly.csc.model.csc.requests;

import com.czertainly.csc.model.CertificateRevocationReason;

import java.util.UUID;

public record RemoveCredentialRequest(
        UUID credentialID,
        CertificateRevocationReason revocationReason
) {
}
