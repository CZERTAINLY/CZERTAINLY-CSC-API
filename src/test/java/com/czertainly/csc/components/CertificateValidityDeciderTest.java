package com.czertainly.csc.components;

import com.czertainly.csc.clients.ejbca.EjbcaClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.RevocationStatus;
import com.czertainly.csc.model.csc.CertificateStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CertificateValidityDeciderTest {

    private DateConverter dateConverter;
    private EjbcaClient ejbcaClient;
    private CertificateValidityDecider validityDecider;

    @BeforeEach
    void setUp() {
        dateConverter = new DateConverter();
        ejbcaClient = mock(EjbcaClient.class);
        validityDecider = new CertificateValidityDecider(dateConverter, ejbcaClient);
    }

    @Test
    void decideStatusValidCertificate() {
        // given
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getNotBefore()).thenReturn(new Date(System.currentTimeMillis() - 100000));
        when(certificate.getNotAfter()).thenReturn(new Date(System.currentTimeMillis() + 100000));
        when(certificate.getSerialNumber()).thenReturn(BigInteger.valueOf(123456));
        when(certificate.getIssuerX500Principal()).thenReturn(new X500Principal("CN=Test Issuer"));

        when(ejbcaClient.getCertificateRevocationStatus(anyString(), anyString()))
                .thenReturn(Result.success(RevocationStatus.NOT_REVOKED));

        // when
        Result<CertificateStatus, TextError> result = validityDecider.decideStatus(certificate);

        // then
        assertNotNull(result.unwrap());
        assertEquals(CertificateStatus.VALID, result.unwrap());
    }

    @Test
    void decideStatusExpiredCertificate() {
        // given
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getNotBefore()).thenReturn(new Date(System.currentTimeMillis() - 200000));
        when(certificate.getNotAfter()).thenReturn(new Date(System.currentTimeMillis() - 100000));

        // when
        Result<CertificateStatus, TextError> result = validityDecider.decideStatus(certificate);

        // then
        assertNotNull(result.unwrap());
        assertEquals(CertificateStatus.EXPIRED, result.unwrap());
    }

    @Test
    void decideStatusNotYetValidCertificate() {
        // given
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getNotBefore()).thenReturn(new Date(System.currentTimeMillis() + 100000));
        when(certificate.getNotAfter()).thenReturn(new Date(System.currentTimeMillis() + 200000));

        // when
        Result<CertificateStatus, TextError> result = validityDecider.decideStatus(certificate);

        // then
        assertNotNull(result.unwrap());
        assertEquals(CertificateStatus.NOT_YET_VALID, result.unwrap());
    }

    @Test
    void decideStatusWithRevocation() {
        // given
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getNotBefore()).thenReturn(new Date(System.currentTimeMillis() - 100000));
        when(certificate.getNotAfter()).thenReturn(new Date(System.currentTimeMillis() + 100000));
        when(certificate.getSerialNumber()).thenReturn(BigInteger.valueOf(123456));
        when(certificate.getIssuerX500Principal()).thenReturn(new X500Principal("CN=Test Issuer"));
        when(ejbcaClient.getCertificateRevocationStatus(anyString(), anyString()))
                .thenReturn(Result.success(RevocationStatus.REVOKED));

        // when
        Result<CertificateStatus, TextError> result = validityDecider.decideStatus(certificate);

        // then
        assertNotNull(result.unwrap());
        assertEquals(CertificateStatus.REVOKED, result.unwrap());
    }
}
