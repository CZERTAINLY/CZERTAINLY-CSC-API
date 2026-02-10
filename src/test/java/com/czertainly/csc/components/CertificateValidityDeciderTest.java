package com.czertainly.csc.components;

import com.czertainly.csc.clients.ejbca.EjbcaClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.RevocationStatus;
import com.czertainly.csc.model.csc.CertificateStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

class CertificateValidityDeciderTest {

    private EjbcaClient ejbcaClient;
    private CertificateValidityDecider validityDecider;

    @BeforeEach
    void setUp() {
        DateConverter dateConverter = new DateConverter();
        ejbcaClient = mock(EjbcaClient.class);
        validityDecider = new CertificateValidityDecider(dateConverter, ejbcaClient);
    }

    @Test
    void decideStatusValidCertificate() {
        // given
        X509CertificateHolder certificate = mock(X509CertificateHolder.class);
        when(certificate.getNotBefore()).thenReturn(new Date(System.currentTimeMillis() - 100000));
        when(certificate.getNotAfter()).thenReturn(new Date(System.currentTimeMillis() + 100000));
        when(certificate.getSerialNumber()).thenReturn(BigInteger.valueOf(123456));
        when(certificate.getIssuer()).thenReturn(new X500Name("CN=Test Issuer"));

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
        X509CertificateHolder certificate = mock(X509CertificateHolder.class);
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
        X509CertificateHolder certificate = mock(X509CertificateHolder.class);
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
        X509CertificateHolder certificate = mock(X509CertificateHolder.class);
        when(certificate.getNotBefore()).thenReturn(new Date(System.currentTimeMillis() - 100000));
        when(certificate.getNotAfter()).thenReturn(new Date(System.currentTimeMillis() + 100000));
        when(certificate.getSerialNumber()).thenReturn(BigInteger.valueOf(123456));
        when(certificate.getIssuer()).thenReturn(new X500Name("CN=Test Issuer"));
        when(ejbcaClient.getCertificateRevocationStatus(anyString(), anyString()))
                .thenReturn(Result.success(RevocationStatus.REVOKED));

        // when
        Result<CertificateStatus, TextError> result = validityDecider.decideStatus(certificate);

        // then
        assertNotNull(result.unwrap());
        assertEquals(CertificateStatus.REVOKED, result.unwrap());
    }
}
