package com.otilm.csc.model.csc;

import com.otilm.csc.service.keys.SigningKey;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Represents a metadata for a credential created based on the Signature Qualifier Profile
 */
public record SignatureQualifierBasedCredentialMetadata<K extends SigningKey>(
        String userId,
        K key,
        String endEntityName,
        X509CertificateHolder certificate,
        String signatureQualifier,
        int multisign
) {}
