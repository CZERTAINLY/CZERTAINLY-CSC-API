package com.czertainly.csc.crypto;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

@Component
public class CertificateParser {

    private static final Logger logger = LoggerFactory.getLogger(CertificateParser.class);

    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

    public CertificateParser() throws CertificateException {
    }

    public Result<X509Certificate, TextError> parseDerEncodedCertificate(byte[] derEncodedCertificate) {
        try {
            var certificate = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(derEncodedCertificate));
            return Result.success(certificate);
        } catch (CertificateException e) {
            return Result.error(
                    TextError.of("Failed to parse DER encoded certificate into X509Certificate. {}", e.getMessage()));
        }
    }

    public Result<Collection<X509CertificateHolder>, TextError> parsePkcs7Chain(byte[] pkcs7Chain) {
        try {
            CMSSignedData signedData = new CMSSignedData(new ByteArrayInputStream(pkcs7Chain));
            Store<X509CertificateHolder> certStore = signedData.getCertificates();
            return Result.success(certStore.getMatches(null));
        } catch (Exception e) {
            logger.error("Parsing of PKCS7 certificate chain has failed.", e);
            return Result.error(TextError.of(e));
        }
    }

    public Result<X509CertificateHolder, TextError> getEndCertificateFromPkcs7Chain(byte[] pkcs7Chain) {
        return parsePkcs7Chain(pkcs7Chain)
                .flatMap(chain -> {
                    var firstCertificate = chain.stream().findFirst();
                    return firstCertificate.<Result<X509CertificateHolder, TextError>>map(Result::success)
                                           .orElseGet(() -> Result.error(TextError.of("")));
                });
    }

}