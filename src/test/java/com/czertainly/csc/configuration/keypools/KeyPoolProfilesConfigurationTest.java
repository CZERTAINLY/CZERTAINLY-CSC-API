package com.czertainly.csc.configuration.keypools;

import com.czertainly.csc.utils.TestValidationErrors;
import com.czertainly.csc.utils.configuration.KeyPoolProfileBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.validation.Errors;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class KeyPoolProfilesConfigurationTest {

    KeyPoolProfilesConfiguration validator = new KeyPoolProfilesConfiguration(List.of());
    Errors errors;

    @BeforeEach
    void initErrors() {
        errors = new TestValidationErrors();
    }

    @Test
    void missingKeyPoolProfilesProduceConfigurationError() {
        // given
        List<KeyPoolProfile> missingProfiles = null;
        KeyPoolProfilesConfiguration keyPoolProfilesConfiguration = new KeyPoolProfilesConfiguration(missingProfiles);

        // when
        validator.validate(keyPoolProfilesConfiguration, errors);

        // then
        assertEquals(1, errors.getFieldErrors().size());
        assertEquals("keyPoolProfiles.empty", errors.getFieldErrors().getFirst().getCode());
    }

    @Test
    void emptyKeyPoolProfilesProduceConfigurationError() {
        // given
        List<KeyPoolProfile> emptyProfiles = List.of();
        KeyPoolProfilesConfiguration keyPoolProfilesConfiguration = new KeyPoolProfilesConfiguration(emptyProfiles);

        // when
        validator.validate(keyPoolProfilesConfiguration, errors);

        // then
        assertEquals(1, errors.getFieldErrors().size());
        assertEquals("keyPoolProfiles.empty", errors.getFieldErrors().getFirst().getCode());
    }

    @Test
    void duplicateKeyPoolProfilesProduceConfigurationError() {
        // KeyPools with the same key algorithm, key specification and designated usage are not allowed
        // given
        KeyPoolProfile profile1 = KeyPoolProfileBuilder.create()
                                                        .withName("profile1")
                                                       .withDesignatedUsage(KeyUsageDesignation.SESSION_SIGNATURE)
                                                       .withKeyAlgorithm("RSA")
                                                       .withKeySpecification("2048")
                                                       .build();
        KeyPoolProfile profile2 = KeyPoolProfileBuilder.create()
                                                       .withName("profile2")
                                                       .withDesignatedUsage(KeyUsageDesignation.SESSION_SIGNATURE)
                                                       .withKeyAlgorithm("RSA")
                                                       .withKeySpecification("2048")
                                                       .build();
        List<KeyPoolProfile> duplicateProfiles = List.of(profile1, profile2);
        KeyPoolProfilesConfiguration keyPoolProfilesConfiguration = new KeyPoolProfilesConfiguration(duplicateProfiles);

        // when
        validator.validate(keyPoolProfilesConfiguration, errors);

        // then
        assertEquals(1, errors.getFieldErrors().size());
        assertEquals("keyPoolProfiles.interfere", errors.getFieldErrors().getFirst().getCode());
    }


    @Test
    void uniqueKeyPoolProfilesDoNotProduceConfigurationError() {
        // given
        KeyPoolProfile profile1 = KeyPoolProfileBuilder.create()
                                                        .withName("profile1")
                                                        .withDesignatedUsage(KeyUsageDesignation.SESSION_SIGNATURE)
                                                        .withKeyAlgorithm("RSA")
                                                        .withKeySpecification("2048")
                                                        .build();
        KeyPoolProfile profile2 = KeyPoolProfileBuilder.create()
                                                        .withName("profile2")
                                                        .withDesignatedUsage(KeyUsageDesignation.SESSION_SIGNATURE)
                                                        .withKeyAlgorithm("RSA")
                                                        .withKeySpecification("4096")
                                                        .build();
        List<KeyPoolProfile> uniqueProfiles = List.of(profile1, profile2);
        KeyPoolProfilesConfiguration keyPoolProfilesConfiguration = new KeyPoolProfilesConfiguration(uniqueProfiles);

        // when
        validator.validate(keyPoolProfilesConfiguration, errors);

        // then
        assertEquals(0, errors.getFieldErrors().size());
    }

    @Test
    void validConfigurationProducesNoErrors() {
        // given
        KeyPoolProfile profile1 = KeyPoolProfileBuilder.create()
                                                       .withName("profile1")
                                                       .withDesignatedUsage(KeyUsageDesignation.ONE_TIME_SIGNATURE)
                                                       .withKeyAlgorithm("ECDSA")
                                                       .withKeySpecification("prime256v1")
                                                       .build();
        KeyPoolProfile profile2 = KeyPoolProfileBuilder.create()
                                                       .withName("profile2")
                                                       .withDesignatedUsage(KeyUsageDesignation.SESSION_SIGNATURE)
                                                       .withKeyAlgorithm("RSA")
                                                       .withKeySpecification("4096")
                                                       .build();
        List<KeyPoolProfile> uniqueProfiles = List.of(profile1, profile2);
        KeyPoolProfilesConfiguration keyPoolProfilesConfiguration = new KeyPoolProfilesConfiguration(uniqueProfiles);

        // when
        validator.validate(keyPoolProfilesConfiguration, errors);

        // then
        assertEquals(0, errors.getFieldErrors().size());
    }

}