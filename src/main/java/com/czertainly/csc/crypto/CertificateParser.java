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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class CertificateParser {

    private static final Logger logger = LoggerFactory.getLogger(CertificateParser.class);

    public Result<X509CertificateHolder, TextError> parseDerEncodedCertificate(byte[] derEncodedCertificate) {
        try {
            X509CertificateHolder certificateHolder = new X509CertificateHolder(derEncodedCertificate);
            return Result.success(certificateHolder);
        } catch (Exception e) {
            return Result.error(
                    TextError.of("Failed to parse DER encoded certificate into X509CertificateHolder. %s", e.getMessage()));
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

    public Result<List<byte[]>, TextError> parsePkcs7ChainToList(byte[] pkcs7Chain) {
        return parsePkcs7Chain(pkcs7Chain)
                .flatMap(chain -> {
                    List<byte[]> certificates = new ArrayList<>();
                    for (X509CertificateHolder certHolder : chain) {
                        try {
                            certificates.add(certHolder.getEncoded());
                        } catch (Exception e) {
                            logger.error("Failed to encode certificate from PKCS7 chain.", e);
                            return Result.error(TextError.of("Failed to encode certificate: %s", e.getMessage()));
                        }
                    }
                    return Result.success(certificates);
                });
    }
}
