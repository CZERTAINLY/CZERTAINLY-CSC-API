package com.czertainly.csc.api.auth;

import com.czertainly.csc.api.auth.exceptions.JwkLookupException;
import com.czertainly.csc.utils.cert.CertificateUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

import static com.czertainly.csc.utils.jwt.Constants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class JwksRepositoryTest {

    @Mock
    private JwksDownloader jwksDownloader;

    @Spy
    private JwksParser jwksParser = new JwksParser();

    @InjectMocks
    JwksRepository jwksRepository;

    void mockKeyDownload() {
        when(jwksDownloader.download()).thenReturn(JWKS_STRING);
    }

    @Test
    void canReturnSigningKey() throws CertificateException {
        // setup
        mockKeyDownload();

        // given
        String kid = JWKS_SIG_KID;
        PublicKey expectedSigPublicKey = CertificateUtils.extractPublicKeyFromCertificateString(JWKS_SIG_X5T);

        // when
        PublicKey key = jwksRepository.getKey(kid, "sig");

        // then
        compareKeys(expectedSigPublicKey, key);
    }

    @Test
    void canReturnEncryptionKey() throws CertificateException {
        // setup
        mockKeyDownload();

        // given
        String kid = JWKS_ENC_KID;
        PublicKey expectedEncPublicKey = CertificateUtils.extractPublicKeyFromCertificateString(JWKS_ENC_X5T);

        // when
        PublicKey key = jwksRepository.getKey(kid, "enc");

        // then
        compareKeys(expectedEncPublicKey, key);
    }

    @Test
    void canRefreshKeys() throws CertificateException {
        // setup
        mockKeyDownload();

        // given
        String kid = JWKS_SIG_KID;

        // when
        PublicKey key = jwksRepository.getKey(kid, "sig");

        // then
        verify(jwksDownloader).download();

    }

    @Test
    void getKey() {
        // given
        String unknownUsage = "unknown-usage";

        // when
        Executable exec = () -> jwksRepository.getKey("arbitrary-kid", unknownUsage);

        // then
        assertThrows(JwkLookupException.class, exec, "Unknown key usage: " + unknownUsage);
    }


    private void compareKeys(PublicKey key1, PublicKey key2) {
        assertEquals(key1.getAlgorithm(), key2.getAlgorithm());
        assertEquals(key1.getFormat(), key2.getFormat());

        if (key1 instanceof RSAPublicKey k1 && key2 instanceof RSAPublicKey k2) {
            assertEquals(k1.getModulus(), k2.getModulus());
            assertEquals(k1.getPublicExponent(), k2.getPublicExponent());
        } else {
            fail("The keys are not of a same type or the type is not supported.");
        }
    }

}