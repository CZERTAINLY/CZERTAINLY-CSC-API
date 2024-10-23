package com.czertainly.csc.signing.configuration.profiles.credentialprofile;

import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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

import static com.czertainly.csc.signing.configuration.profiles.ConfigurationUtils.*;

@Component
public class CredentialProfileLoader {

    private static final Logger logger = LoggerFactory.getLogger(CredentialProfileLoader.class);
    private final List<CredentialProfile> credentialProfiles;

    public CredentialProfileLoader(
            @Value("${csc.profilesConfigurationDirectory}") String configurationDirectoryPath,
            @Value("credential-profiles-ejbca.yml") String configurationFileName
    ) {
        logger.info("Loading credential profiles from '{}/{}'", configurationDirectoryPath, configurationFileName);
        var getConfigurationFileResult = checkFileExistenceAndGet(configurationDirectoryPath, configurationFileName);
        if (getConfigurationFileResult instanceof Error(var e)) {
            throw new ApplicationConfigurationException(e.getErrorText());
        }
        File configurationFile = getConfigurationFileResult.unwrap();
        try {
            Yaml yaml = new Yaml(new Constructor(CredentialProfilesConfigurationFile.class, new LoaderOptions()));
            CredentialProfilesConfigurationFile configuration = yaml.load(
                    new BufferedReader(new FileReader(configurationFile))
            );
            if (configuration == null) {
                throw new ApplicationConfigurationException("Configuration file is empty.");
            }
            var getCredentialProfiles = parseAndValidateProfiles(configuration);
            if (getCredentialProfiles instanceof Error(var e)) {
                throw new ApplicationConfigurationException(e.getErrorText());
            }
            credentialProfiles = getCredentialProfiles.unwrap();

        } catch (FileNotFoundException e) {
            throw new ApplicationConfigurationException("Worker configuration file not found.", e);
        } catch (ConstructorException e) {
            throw new ApplicationConfigurationException("Failed to parse configuration file.", e);
        }
    }

    public List<CredentialProfile> getProfiles() {
        return credentialProfiles;
    }

    private Result<List<CredentialProfile>, TextError> parseAndValidateProfiles(
            CredentialProfilesConfigurationFile configuration
    ) {
        List<CredentialProfile> credentialProfiles = new ArrayList<>();
        for (CredentialProfileConfiguration credentialProfileConfiguration : configuration.getProfiles()) {
            var profileResult = parseAndValidateProfile(credentialProfileConfiguration);
            if (profileResult instanceof Error(var e)) {
                String profileName = credentialProfileConfiguration.getName();
                if (profileName != null) {
                    return Result.error(e.extend("Failed to parse credential profile %s.", profileName));
                } else {
                    return Result.error(e.extend("Failed to parse one of the credential profiles."));
                }
            }
            credentialProfiles.add(profileResult.unwrap());
        }
        return Result.success(credentialProfiles);
    }


    private Result<CredentialProfile, TextError> parseAndValidateProfile(CredentialProfileConfiguration configuration) {
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

        var getKeyAlgorithmResult = extractString(configuration::getKeyAlgorithm, "keyAlgorithm");
        if (getKeyAlgorithmResult instanceof Error(var e)) {
            return Result.error(e);
        }
        var keyAlgorithm = getKeyAlgorithmResult.unwrap();

        var getKeySpecificationResult = extractString(configuration::getKeySpecification,
                                                      "keySpecification"
        );
        if (getKeySpecificationResult instanceof Error(var e)) {
            return Result.error(e);
        }
        var keySpecification = getKeySpecificationResult.unwrap();

        var getCsrSignatureAlgorithmResult = extractString(configuration::getCsrSignatureAlgorithm,
                                                           "csrSignatureAlgorithm"
        );
        if (getCsrSignatureAlgorithmResult instanceof Error(var e)) {
            return Result.error(e);
        }
        var csrSignatureAlgorithm = getCsrSignatureAlgorithmResult.unwrap();


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

        CredentialProfile profile = new CredentialProfile(name, certificateAuthority,
                                                          certificateProfileName, endEntityProfileName,
                                                          certificateValidity, certificateValidityOffset,
                                                          keyAlgorithm, keySpecification,
                                                          csrSignatureAlgorithm
        );
        return Result.success(profile);

    }
}
