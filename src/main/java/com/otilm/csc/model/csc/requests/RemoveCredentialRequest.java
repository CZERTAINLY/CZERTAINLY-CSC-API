package com.otilm.csc.model.csc.requests;

import com.otilm.csc.model.CertificateRevocationReason;

import java.util.UUID;

public record RemoveCredentialRequest(
        UUID credentialID,
        CertificateRevocationReason revocationReason
) {
}
