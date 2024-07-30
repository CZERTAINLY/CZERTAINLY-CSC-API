package com.czertainly.csc.crypto;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class CertificateParser {

    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

    public CertificateParser() throws CertificateException {
    }


    public List<X509Certificate> parseDEREncodedCertificates(List<byte[]> derEncodedCertificates) {
        try {
            List<X509Certificate> x509Certificates = new ArrayList<>();
            for (byte[] derEncodedCert : derEncodedCertificates) {
                X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(
                        new ByteArrayInputStream(derEncodedCert));
                x509Certificates.add(certificate);
            }
            return x509Certificates;
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse DER encoded certificate into X509Certificate.", e);
        }
    }

    public X509Certificate parseDerEncodedCertificate(byte[] derEncodedCertificate) {
        try {
            return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(derEncodedCertificate));
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to parse DER encoded certificate into X509Certificate.", e);
        }
    }

    public Collection<X509CertificateHolder> parsePkcs7Chain(byte[] pkcs7Chain) throws CMSException {
        CMSSignedData signedData = new CMSSignedData(new ByteArrayInputStream(pkcs7Chain));
        Store<X509CertificateHolder> certStore = signedData.getCertificates();
        return certStore.getMatches(null);
    }

}