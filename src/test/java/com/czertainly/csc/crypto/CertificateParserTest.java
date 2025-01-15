package com.czertainly.csc.crypto;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import static com.czertainly.csc.utils.ResourceLoader.loadBytesFromResources;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateParserTest {

    private CertificateParser certificateParser = setupCertificateParser();

    @Test
    void parseDerEncodedCertificateSuccess() throws Exception {
        // given
        byte[] bytes = loadBytesFromResources("com/czertainly/csc/crypto/CertificateParserTest.der");

        // when
        Result<X509Certificate, TextError> result = certificateParser.parseDerEncodedCertificate(bytes);

        // then
        X509Certificate parsedCertificate = result.unwrap();
        assertEquals("CN=3Key, O=3Key, L=Prague, ST=Prague, C=CZ", parsedCertificate.getSubjectDN().getName());
    }

    @Test
    void parseDerEncodedCertificateFailure() throws Exception {
        // given
        byte[] bytes = new byte[0];

        // when
        Result<X509Certificate, TextError> result = certificateParser.parseDerEncodedCertificate(bytes);

        // then
        assertTrue(result.unwrapError().getErrorText().contains("Failed to parse DER"));
    }

    @Test
    void parsePkcs7ChainSuccess() throws Exception {
        // given
        byte[] bytes = loadBytesFromResources("com/czertainly/csc/crypto/CertificateParserTest.p7b");

        // when
        Result<Collection<X509CertificateHolder>, TextError> result = certificateParser.parsePkcs7Chain(bytes);

        // then
        Collection<X509CertificateHolder> chain = result.unwrap();
        assertEquals(2, chain.size());
        Iterator<X509CertificateHolder> iterator = chain.iterator();
        assertEquals("C=CZ,L=Prague,O=3Key,CN=3Key", iterator.next().getSubject().toString());
        assertEquals("C=CZ,L=Prague,O=3Key CA,CN=3Key CA", iterator.next().getSubject().toString());
    }

    @Test
    void parsePkcs7ChainFailure() throws Exception {
        // given
        byte[] bytes = new byte[0];

        // when
        Result<Collection<X509CertificateHolder>, TextError> result = certificateParser.parsePkcs7Chain(bytes);

        // then
        assertTrue(result.unwrapError().getErrorText().contains("CMSException"));
    }

    @Test
    void getEndCertificateFromPkcs7ChainSuccess() throws Exception {
        // given
        byte[] bytes = loadBytesFromResources("com/czertainly/csc/crypto/CertificateParserTest.p7b");

        // when
        Result<X509CertificateHolder, TextError> result = certificateParser.getEndCertificateFromPkcs7Chain(bytes);

        // then
        assertEquals("C=CZ,L=Prague,O=3Key,CN=3Key", result.unwrap().getSubject().toString());
    }

    @Test
    void getEndCertificateFromPkcs7ChainFailure() throws Exception {
        // given
        byte[] bytes = new byte[0];

        // when
        Result<X509CertificateHolder, TextError> result = certificateParser.getEndCertificateFromPkcs7Chain(bytes);

        // then
        assertTrue(result.unwrapError().getErrorText().contains("CMSException"));
    }

    private CertificateParser setupCertificateParser() {
        try {
            return new CertificateParser();
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
