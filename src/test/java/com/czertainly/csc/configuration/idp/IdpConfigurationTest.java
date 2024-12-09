package com.czertainly.csc.configuration.idp;

import com.czertainly.csc.utils.TestValidationErrors;
import com.czertainly.csc.utils.configuration.IdpClientAuthBuilder;
import com.czertainly.csc.utils.configuration.IdpClientAuthCertificateBuilder;
import com.czertainly.csc.utils.configuration.IdpConfigurationBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.validation.Errors;

import static org.junit.jupiter.api.Assertions.*;

class IdpConfigurationTest {

    IdpConfiguration validator = new IdpConfiguration(null, null, null, null, null, null, null, null);

    Errors errors;

    @BeforeEach
    void initErrors() {
        errors = new TestValidationErrors();
    }

    @Test
    void missingCertificateGivenAuthIsCertificateProducesError() {
        // given
        IdpClientAuth auth = IdpClientAuthBuilder.create()
                                                 .withAuthType(IdpAuthentication.CERTIFICATE)
                                                 .withCertificate(null)
                                                 .build();
        IdpConfiguration invalidConf = IdpConfigurationBuilder.create()
                                                              .withAuth(auth)
                                                              .build();

        // when
        validator.validate(invalidConf, errors);

        // then
        assertTrue(errors.hasErrors());
        assertEquals(1, errors.getErrorCount());
        assertEquals("certificate.required", errors.getFieldErrors().getFirst().getCode());
    }

    @Test
    void missingKeyStoreBundleGivenAuthIsCertificateProducesError() {
        // given
        IdpClientAuth auth = IdpClientAuthBuilder.create()
                                                 .withAuthType(IdpAuthentication.CERTIFICATE)
                                                 .withCertificate(IdpClientAuthCertificateBuilder.of(null))
                                                 .build();
        IdpConfiguration invalidConf = IdpConfigurationBuilder.create()
                                                              .withAuth(auth)
                                                              .build();

        // when
        validator.validate(invalidConf, errors);

        // then
        assertTrue(errors.hasErrors());
        assertEquals(1, errors.getErrorCount());
        assertEquals("keystoreBundle.required", errors.getFieldErrors().getFirst().getCode());
    }

    @Test
    void validConfigurationDoesNotProduceErrors() {
        // given
        IdpClientAuth auth = IdpClientAuthBuilder.create()
                                                 .withAuthType(IdpAuthentication.CERTIFICATE)
                                                 .withCertificate(IdpClientAuthCertificateBuilder.of("keystore"))
                                                 .build();
        IdpConfiguration validConf = IdpConfigurationBuilder.create()
                                                            .withAuth(auth)
                                                            .build();

        // when
        validator.validate(validConf, errors);

        // then
        assertFalse(errors.hasErrors());
    }

}