package com.czertainly.csc.signing.configuration.profiles;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.signing.configuration.profiles.credentialprofile.CredentialProfile;
import com.czertainly.csc.signing.configuration.profiles.credentialprofile.CredentialProfileLoader;
import com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile.SignatureQualifierProfile;
import com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile.SignatureQualifierProfileLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.stream.Collectors;

@Component
public class CredentialProfileRepository {

    private static final Logger logger = LoggerFactory.getLogger(CredentialProfileRepository.class);
    private final Map<String, CredentialProfile> credentialProfiles;
    private final Map<String, SignatureQualifierProfile> signatureQualifierProfiles;

    public CredentialProfileRepository(CredentialProfileLoader certificateProfileLoader,
                                       SignatureQualifierProfileLoader signatureQualifierProfileLoader
    ) {
        this.credentialProfiles = certificateProfileLoader
                .getProfiles().stream()
                .collect(Collectors.toMap(CredentialProfile::getName, profile -> profile));
        logger.info("Credential Profile Repository initialized with {} credential profiles. [{}]",
                    credentialProfiles.size(), String.join(", ", credentialProfiles.keySet())
        );

        this.signatureQualifierProfiles = signatureQualifierProfileLoader
                .getProfiles().stream()
                .collect(Collectors.toMap(SignatureQualifierProfile::getName, profile -> profile));
        logger.info("Credential Profile Repository initialized with {} signature qualifier profiles. [{}]",
                    signatureQualifierProfiles.size(), String.join(", ", signatureQualifierProfiles.keySet())
        );
    }

    public Result<CredentialProfile, TextError> getCredentialProfile(String name) {
        CredentialProfile p = credentialProfiles.get(name);
        if (p == null) {
            logger.debug("Requested credential profile '{}' not found between known credential profiles: [{}]",
                         name, String.join(", ", credentialProfiles.keySet())
            );
            return Result.error(TextError.of("Requested credential profile '%s' does not exist.", name));
        }
        return Result.success(p);
    }

    public Result<SignatureQualifierProfile, TextError> getSignatureQualifierProfile(String name) {
        SignatureQualifierProfile signatureQualifierProfile = signatureQualifierProfiles.get(name);
        if (signatureQualifierProfile == null) {
            logger.debug(
                    "Requested signature qualifier profile '{}' not found between known signature qualifier profiles: [{}]",
                    name, String.join(", ", signatureQualifierProfiles.keySet())
            );
            return Result.error(

                    TextError.of("Requested signature qualifier profile '%s' does not exist.", name));
        }
        return Result.success(signatureQualifierProfile);
    }
}
