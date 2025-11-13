package com.czertainly.csc.utils.cert;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CertificateUtils {

    public static PublicKey extractPublicKeyFromCertificateString(String pemCertificate) throws CertificateException {
        String base64Der = pemCertificate
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");

        byte[] derCrt = Base64.getDecoder().decode(base64Der);

        // Create a CertificateFactory
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Generate the X509Certificate object
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(derCrt));

        // Extract the public key from the certificate
        return certificate.getPublicKey();
    }
}