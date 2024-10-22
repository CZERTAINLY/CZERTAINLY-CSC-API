package com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile;

import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.providers.PatternDnProvider;
import com.czertainly.csc.providers.PatternSanProvider;
import com.czertainly.csc.providers.PatternUsernameProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.constructor.ConstructorException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static com.czertainly.csc.signing.configuration.profiles.ConfigurationUtils.*;

@Component
public class SignatureQualifierProfileLoader {

    private final List<SignatureQualifierProfile> profiles;


    public SignatureQualifierProfileLoader(
            @Value("${csc.profilesConfigurationDirectory}") String configurationDirectoryPath,
            @Value("signature-qualifier-profiles-ejbca.yml") String configurationFileName
    ) {
        var getConfigurationFileResult = checkFileExistenceAndGet(configurationDirectoryPath, configurationFileName);
        if (getConfigurationFileResult instanceof Error(var e)) {
            throw new ApplicationConfigurationException(e.getErrorText());
        }
        File configurationFile = getConfigurationFileResult.unwrap();
        Yaml yaml = new Yaml(new Constructor(SignatureQualifierProfilesConfigurationFile.class, new LoaderOptions()));

        try {
            SignatureQualifierProfilesConfigurationFile configuration = yaml.load(
                    new BufferedReader(new FileReader(configurationFile))
            );
            if (configuration == null) {
                throw new ApplicationConfigurationException("Configuration file is empty.");
            }
            var getCredentialProfiles = parseAndValidateProfiles(configuration);
            if (getCredentialProfiles instanceof Error(var e)) {
                throw new ApplicationConfigurationException(e.toString());
            }
            profiles = getCredentialProfiles.unwrap();

        } catch (FileNotFoundException e) {
            throw new ApplicationConfigurationException("Configuration file not found.", e);
        } catch (ConstructorException e) {
            throw new ApplicationConfigurationException("Failed to parse configuration file.", e);
        }
    }

    public List<SignatureQualifierProfile> getProfiles() {
        return profiles;
    }

    private Result<List<SignatureQualifierProfile>, TextError> parseAndValidateProfiles(
            SignatureQualifierProfilesConfigurationFile configuration
    ) {
        List<SignatureQualifierProfile> profiles = new ArrayList<>();
        for (SignatureQualifierProfileConfiguration credentialProfileConfiguration : configuration.getProfiles()) {
            var profileResult = parseAndValidateProfile(credentialProfileConfiguration);
            if (profileResult instanceof Error(var e)) {
                String profileName = credentialProfileConfiguration.getName();
                if (profileName != null) {
                    return Result.error(e.extend("Failed to parse signatureQualifier profile %s", profileName));
                } else {
                    return Result.error(e.extend("Failed to parse one of the signatureQualifier profiles"));
                }
            }
            profiles.add(profileResult.unwrap());
        }
        return Result.success(profiles);
    }


    private Result<SignatureQualifierProfile, TextError> parseAndValidateProfile(
            SignatureQualifierProfileConfiguration configuration
    ) {

        var getNameResult = extractString(configuration::getName, "name");
        if (getNameResult instanceof Error(var e)) {
            return Result.error(e);
        }
        var name = getNameResult.unwrap();

        var getCAResult = extractString(configuration::getCaName, "caName");
        if (getCAResult instanceof Error(var e)) {
            return Result.error(e);
        }
        var certificateAuthority = getCAResult.unwrap();

        var getCertificateProfileNameResult = extractString(configuration::getCertificateProfileName,
                                                            "certificateProfileName"
        );
        if (getCertificateProfileNameResult instanceof Error(var e)) {
            return Result.error(e);
        }
        var certificateProfileName = getCertificateProfileNameResult.unwrap();

        var getEndEntityProfileNameResult = extractString(configuration::getEndEntityProfileName,
                                                          "endEntityProfileName"
        );
        if (getEndEntityProfileNameResult instanceof Error(var e)) {
            return Result.error(e);
        }
        var endEntityProfileName = getEndEntityProfileNameResult.unwrap();

        var getCertificateValidityResult = extractDuration(configuration::getCertificateValidity,
                                                           "certificateValidity"
        );
        if (getCertificateValidityResult instanceof Error(var e)) {
            return Result.error(e);
        }
        var certificateValidity = getCertificateValidityResult.unwrap();

        var getCertificateValidityOffsetResult = extractDuration(
                configuration::getCertificateValidityOffset, "certificateValidityOffset");
        if (getCertificateValidityOffsetResult instanceof Error(var e)) {
            return Result.error(e);
        }
        var certificateValidityOffset = getCertificateValidityOffsetResult.unwrap();

        var getUsernamePatternResult = extractString(configuration::getUsernamePattern, "usernamePattern");
        if (getUsernamePatternResult instanceof Error(var e)) {
            return Result.error(e);
        }
        var usernamePattern = getUsernamePatternResult.unwrap();

        var getDistinguishedNameProviderResult = extractNamePattern(configuration::getDn, "dn", false);
        if (getDistinguishedNameProviderResult instanceof Error(var e)) {
            return Result.error(e);
        }
        NamePattern distinguishedNamePattern = getDistinguishedNameProviderResult.unwrap();

        var getSubjectAlternativeNameResult = extractNamePattern(configuration::getSan, "san", true);
        if (getSubjectAlternativeNameResult instanceof Error(var e)) {
            return Result.error(e);
        }
        NamePattern subjectAlternativeNamePattern = getSubjectAlternativeNameResult.unwrap();

        SignatureQualifierProfile profile = new SignatureQualifierProfile(
                name, certificateAuthority,
                certificateProfileName, endEntityProfileName,
                certificateValidity,
                certificateValidityOffset,
                new PatternUsernameProvider(usernamePattern),
                new PatternDnProvider(
                        distinguishedNamePattern.getPattern(),
                        distinguishedNamePattern.getRequired()
                ),
                new PatternSanProvider(
                        subjectAlternativeNamePattern.getPattern(),
                        subjectAlternativeNamePattern.getRequired()
                )
        );
        return Result.success(profile);
    }

    @NonNull
    public static Result<NamePattern, TextError> extractNamePattern(Supplier<NamePattern> supplier, String patternName,
                                                                    Boolean canBeEmpty
    ) {
        NamePattern value = supplier.get();
        if (value == null && !canBeEmpty) {
            return Result.error(
                    TextError.of(
                            "Missing value for '%s' property.",
                            patternName
                    )
            );
        } else if (value == null && canBeEmpty) {
            return Result.success(new NamePattern(null, List.of()));
        }

        if ((value.getPattern() == null || value.getPattern().isEmpty()) && !canBeEmpty) {
            return Result.error(
                    TextError.of(
                            "Missing value for 'pattern' property in %s.",
                            patternName
                    )
            );
        }

        if ((value.getRequired() == null || value.getRequired().isEmpty()) && !canBeEmpty) {
            return Result.error(
                    TextError.of(
                            "Missing value for 'required' property in %s.",
                            patternName
                    )
            );
        }

        return Result.success(value);
    }


}