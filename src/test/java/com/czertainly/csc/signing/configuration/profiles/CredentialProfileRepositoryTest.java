package com.czertainly.csc.signing.configuration.profiles;

import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Success;
import com.czertainly.csc.signing.configuration.profiles.credentialprofile.CredentialProfile;
import com.czertainly.csc.signing.configuration.profiles.credentialprofile.CredentialProfileLoader;
import com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile.SignatureQualifierProfile;
import com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile.SignatureQualifierProfileLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialProfileRepositoryTest {

    @Mock
    CredentialProfileLoader credentialProfileLoader;

    @Mock
    SignatureQualifierProfileLoader signatureQualifierProfileLoader;

    CredentialProfileRepository credentialProfileRepository;

    @BeforeEach
    void setUp() {
        when(credentialProfileLoader.getProfiles()).thenReturn(List.of(aCredentialProfile()));
        when(signatureQualifierProfileLoader.getProfiles()).thenReturn(List.of(aSignatureQualifierProfile()));
        credentialProfileRepository = new CredentialProfileRepository(
                credentialProfileLoader,
                signatureQualifierProfileLoader
        );
    }

    @Test
    void returnsCredentialProfileIfExists() {
        // given
        String profileName = "myCredentialProfile";

        // when
        var result = credentialProfileRepository.getCredentialProfile(profileName);

        // then
        assertInstanceOf(Success.class, result);
        CredentialProfile profile = result.unwrap();
        assertEquals("myCredentialProfile", profile.getName());
    }

    @Test
    void returnErrorWhenCredentialProfileDoesNotExist() {
        // given
        String profileName = "nonExistingProfile";

        // when
        var result = credentialProfileRepository.getCredentialProfile(profileName);

        // then
        assertInstanceOf(Error.class, result);
        assertTrue(result.unwrapError().getErrorText()
                         .contains("credential profile 'nonExistingProfile' does not exist"));
    }

    @Test
    void returnsSignatureQualifierProfileIfExists() {
        // given
        String profileName = "mySignatureQualifierProfile";

        // when
        var result = credentialProfileRepository.getSignatureQualifierProfile(profileName);

        // then
        assertInstanceOf(Success.class, result);
        SignatureQualifierProfile profile = result.unwrap();
        assertEquals("mySignatureQualifierProfile", profile.getName());
    }

    @Test
    void returnErrorWhenSignatureQualifierDoesNotExist() {
        // given
        String profileName = "nonExistingProfile";

        // when
        var result = credentialProfileRepository.getSignatureQualifierProfile(profileName);

        // then
        assertInstanceOf(Error.class, result);
        assertTrue(result.unwrapError().getErrorText()
                         .contains("signature qualifier profile 'nonExistingProfile' does not exist"));
    }

    private CredentialProfile aCredentialProfile() {
        return new CredentialProfile(
                "myCredentialProfile",
                "MyCA",
                "MyCertificateProfile",
                "MyEndEntityProfile",
                Duration.ofDays(365),
                Duration.ofMinutes(-1),
                "keyAlgorithm",
                "keySpecification",
                "csrSignatureAlgorithm"
        );
    }

    private SignatureQualifierProfile aSignatureQualifierProfile() {
        return new SignatureQualifierProfile(
                "mySignatureQualifierProfile",
                "MyCA",
                "MyCertificateProfile",
                "MyEndEntityProfile",
                Duration.ofDays(365),
                Duration.ofMinutes(-1),
                "SHA256withRSA",
                null,
                null,
                null,
                1
        );
    }
}
