package com.czertainly.csc.signing.configuration.profiles;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.signing.configuration.profiles.credentialprofile.CredentialProfile;
import com.czertainly.csc.signing.configuration.profiles.credentialprofile.CredentialProfileLoader;
import com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile.SignatureQualifierProfile;
import com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile.SignatureQualifierProfileLoader;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.stream.Collectors;

@Component
public class CredentialProfileRepository {

    private final Map<String, CredentialProfile> credentialProfiles;
    private final Map<String, SignatureQualifierProfile> signatureQualifierProfiles;

    public CredentialProfileRepository(CredentialProfileLoader certificateProfileLoader,
                                       SignatureQualifierProfileLoader signatureQualifierProfileLoader
    ) {
        this.credentialProfiles = certificateProfileLoader
                .getProfiles().stream()
                .collect(Collectors.toMap(CredentialProfile::getName, profile -> profile));
        this.signatureQualifierProfiles = signatureQualifierProfileLoader
                .getProfiles().stream()
                .collect(Collectors.toMap(SignatureQualifierProfile::getName, profile -> profile));

    }

    public Result<CredentialProfile, TextError> getCredentialProfile(String name) {
        CredentialProfile p = credentialProfiles.get(name);
        if (p == null) {
            return Result.error(TextError.of("Requested credential profile '%s' does not exist.", name));
        }
        return Result.success(p);
    }

    public Result<SignatureQualifierProfile, TextError> getSignatureQualifierProfile(String signatureQualifier) {
        SignatureQualifierProfile signatureQualifierProfile = signatureQualifierProfiles.get(signatureQualifier);
        if (signatureQualifierProfile == null) {
            return Result.error(
                    TextError.of("Requested signature qualifier profile '%s' does not exist.", signatureQualifier));
        }
        return Result.success(signatureQualifierProfile);
    }
}
