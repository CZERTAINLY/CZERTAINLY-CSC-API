package com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile;

import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.configuration.csc.CscConfiguration;
import com.czertainly.csc.providers.DistinguishedNameProvider;
import com.czertainly.csc.providers.SubjectAlternativeNameProvider;
import com.czertainly.csc.providers.UsernameProvider;
import com.czertainly.csc.utils.configuration.CscConfigurationBuilder;
import org.instancio.Instancio;
import org.instancio.InstancioApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static com.czertainly.csc.utils.assertions.ExceptionAssertions.assertThrowsAndMessageContains;
import static org.instancio.Select.field;
import static org.junit.jupiter.api.Assertions.*;

class SignatureQualifierProfileLoaderTest {

    Path configurationDirectory = Files.createTempDirectory("configs");
    CscConfiguration cscConfiguration = new CscConfigurationBuilder()
            .withProfilesConfigurationDirectory(configurationDirectory.toString())
            .build();

    SignatureQualifierProfileLoaderTest() throws IOException {}

    @Test
    void loadSignatureQualifierProfilesCanLoadEmptyProfilesConfiguration() {
        // given
        File config = prepareConfigurationFile(List.of());

        // when
        SignatureQualifierProfileLoader loader = new SignatureQualifierProfileLoader(cscConfiguration,
                                                                                     config.getName()
        );

        // then
        assertTrue(loader.getProfiles().isEmpty());
    }

    @Test
    void loadSignatureQualifierProfilesCanLoadProfilesConfiguration() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().create(), aSignatureQualifierProfileConfiguration().create());
        File config = prepareConfigurationFile(profiles);

        // when
        SignatureQualifierProfileLoader loader = new SignatureQualifierProfileLoader(cscConfiguration,
                                                                                     config.getName()
        );

        // then
        assertEquals(2, loader.getProfiles().size());
    }

    @Test
    void loadSignatureQualifierProfilesLoadsConfigurationCorrectly() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().create()); File config = prepareConfigurationFile(profiles);

        // when
        SignatureQualifierProfileLoader loader = new SignatureQualifierProfileLoader(cscConfiguration,
                                                                                     config.getName()
        );

        // then
        assertEquals(1, loader.getProfiles().size());
        SignatureQualifierProfile profile = loader.getProfiles().getFirst();
        assertEquals("profile1", profile.getName()); assertEquals("aCA", profile.getCertificateAuthority());
        assertEquals("CertProfile1", profile.getCertificateProfileName());
        assertEquals("EndEntityProfile1", profile.getEndEntityProfileName());
        assertEquals(Duration.ofDays(365), profile.getCertificateValidity());
        assertEquals(Duration.ZERO, profile.getCertificateValidityOffset());
        assertEquals("SHA256WithRSA", profile.getCsrSignatureAlgorithm());
        assertInstanceOf(UsernameProvider.class, profile.getUsernameProvider());
        assertInstanceOf(DistinguishedNameProvider.class, profile.getDistinguishedNameProvider());
        assertInstanceOf(SubjectAlternativeNameProvider.class, profile.getSubjectAlternativeNameProvider());
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfConfigurationFileDoesNotExist() throws IOException {
        // given
        String dir = Files.createTempDirectory("configs").toString();
        CscConfiguration cscConfiguration = new CscConfigurationBuilder()
                .withProfilesConfigurationDirectory(dir)
                .build();
        String configurationFile = "non-existing-file.yml";

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, configurationFile);

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class, "does not exist", ex);
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfConfigurationFileIsEmpty() throws IOException {
        // given
        File config = File.createTempFile("siqnature-qualifier-profiles-ejbca", "yml");

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class, "Configuration file is empty", ex);
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfConfigurationFileIsInvalid() throws IOException {
        // given
        File config = File.createTempFile("siqnature-qualifier-profiles-ejbca", "yml");
        try (FileWriter writer = new FileWriter(config)) {
            writer.write("invalid yaml");
        }

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class, "Failed to parse configuration file.",
                                       ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingName() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().set(field(SignatureQualifierProfileConfiguration::getName),
                                                              null
                ).create()); File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class, "Missing value for 'name' property",
                                       ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingCaName() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().set(field(SignatureQualifierProfileConfiguration::getCaName),
                                                              null
                ).create()); File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class, "Missing value for 'caName' property",
                                       ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingCertificateProfileName() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(aSignatureQualifierProfileConfiguration().set(
                field(SignatureQualifierProfileConfiguration::getCertificateProfileName), null).create());
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class,
                                       "Missing value for 'certificateProfileName' property", ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingEndEntityProfileName() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(aSignatureQualifierProfileConfiguration().set(
                field(SignatureQualifierProfileConfiguration::getEndEntityProfileName), null).create());
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class,
                                       "Missing value for 'endEntityProfileName' property", ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingCertificateValidity() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(aSignatureQualifierProfileConfiguration().set(
                field(SignatureQualifierProfileConfiguration::getCertificateValidity), null).create());
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class,
                                       "Missing value for 'certificateValidity' property", ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileHasInvalidCertificateValidity() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(aSignatureQualifierProfileConfiguration().set(
                field(SignatureQualifierProfileConfiguration::getCertificateValidity), "not-ISO-8601").create());
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class,
                                       "Invalid duration format for 'certificateValidity'", ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingCertificateValidityOffset() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(aSignatureQualifierProfileConfiguration().set(
                field(SignatureQualifierProfileConfiguration::getCertificateValidityOffset), null).create());
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class,
                                       "Missing value for 'certificateValidityOffset' property", ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileHasInvalidCertificateValidityOffset() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(aSignatureQualifierProfileConfiguration().set(
                field(SignatureQualifierProfileConfiguration::getCertificateValidityOffset), "not-ISO-8601").create());
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class,
                                       "Invalid duration format for 'certificateValidityOffset'", ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingCsrSignatureAlgorithm() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(aSignatureQualifierProfileConfiguration().set(
                field(SignatureQualifierProfileConfiguration::getCsrSignatureAlgorithm), null).create());
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class,
                                       "Missing value for 'csrSignatureAlgorithm' property", ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingUsernamePattern() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(aSignatureQualifierProfileConfiguration().set(
                field(SignatureQualifierProfileConfiguration::getUsernamePattern), null).create());
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class, "Missing value for 'usernamePattern'",
                                       ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingDNPattern() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().set(field(SignatureQualifierProfileConfiguration::getDn),
                                                              null
                ).create()); File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class, "Missing value for 'dn'", ex);
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfilesDNPatternIsMissingPattern() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().set(field(SignatureQualifierProfileConfiguration::getDn),
                                                              new NamePattern(null, List.of("CN"))
                ).create()); File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class,
                                       "Missing value for 'pattern' property in dn", ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfilesDNPatternIsMissingRequiredParts() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().set(field(SignatureQualifierProfileConfiguration::getDn),
                                                              new NamePattern("CN=XY", null)
                ).create()); File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class,
                                       "Missing value for 'required' property in dn", ex
        );
    }

    @Test
    void loadCredentialProfilesLoadsSuccessfullyIfProfileIsMissingSANPattern() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().set(field(SignatureQualifierProfileConfiguration::getSan),
                                                              null
                ).create()); File config = prepareConfigurationFile(profiles);

        // when
        SignatureQualifierProfileLoader loader = new SignatureQualifierProfileLoader(cscConfiguration,
                                                                                     config.getName()
        );

        // then
        SignatureQualifierProfile profile = loader.getProfiles().getFirst();
        assertInstanceOf(SubjectAlternativeNameProvider.class, profile.getSubjectAlternativeNameProvider());
    }

    @Test
    void loadCredentialProfilesLoadsSuccessfullyIfProfileIsMissingPatternInSAN() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().set(field(SignatureQualifierProfileConfiguration::getSan),
                                                              new NamePattern(null, List.of())
                ).create()); File config = prepareConfigurationFile(profiles);

        // when
        SignatureQualifierProfileLoader loader = new SignatureQualifierProfileLoader(cscConfiguration,
                                                                                     config.getName()
        );

        // then
        SignatureQualifierProfile profile = loader.getProfiles().getFirst();
        assertInstanceOf(SubjectAlternativeNameProvider.class, profile.getSubjectAlternativeNameProvider());
    }

    @Test
    void loadCredentialProfilesLoadsSuccessfullyIfProfileIsMissingRequiredInSAN() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().set(field(SignatureQualifierProfileConfiguration::getSan),
                                                              new NamePattern("XY", null)
                ).create()); File config = prepareConfigurationFile(profiles);

        // when
        SignatureQualifierProfileLoader loader = new SignatureQualifierProfileLoader(cscConfiguration,
                                                                                     config.getName()
        );

        // then
        SignatureQualifierProfile profile = loader.getProfiles().getFirst();
        assertInstanceOf(SubjectAlternativeNameProvider.class, profile.getSubjectAlternativeNameProvider());
    }


    @Test
    void loadCredentialProfilesExceptionContainsNameOfTheInvalidProfile() {
        // given
        List<SignatureQualifierProfileConfiguration> profiles = List.of(
                aSignatureQualifierProfileConfiguration().set(field(SignatureQualifierProfileConfiguration::getName),
                                                              "myProfile"
                ).set(field(SignatureQualifierProfileConfiguration::getCertificateProfileName), null).create());
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new SignatureQualifierProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(ApplicationConfigurationException.class, "myProfile", ex);
    }


    private File prepareConfigurationFile(List<SignatureQualifierProfileConfiguration> profiles) {
        try {
            Path f = Files.createTempFile(configurationDirectory, "credential-profiles-ejbca", ".yml");
            DumperOptions options = new DumperOptions(); options.setIndent(2); options.setPrettyFlow(true);
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);

            Representer representer = new Representer(options);
            representer.addClassTag(SignatureQualifierProfilesConfigurationFile.class, Tag.MAP);
            Yaml yaml = new Yaml(representer, options);

            SignatureQualifierProfilesConfigurationFile configuration = new SignatureQualifierProfilesConfigurationFile();
            configuration.setProfiles(profiles); try (FileWriter writer = new FileWriter(f.toFile())) {
                yaml.dump(configuration, writer);
            } return f.toFile();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    private InstancioApi<SignatureQualifierProfileConfiguration> aSignatureQualifierProfileConfiguration() {
        return Instancio.of(SignatureQualifierProfileConfiguration.class)
                        .set(field(SignatureQualifierProfileConfiguration::getName), "profile1")
                        .set(field(SignatureQualifierProfileConfiguration::getCaName), "aCA")
                        .set(field(SignatureQualifierProfileConfiguration::getCertificateProfileName), "CertProfile1")
                        .set(field(SignatureQualifierProfileConfiguration::getEndEntityProfileName),
                             "EndEntityProfile1"
                        ).set(field(SignatureQualifierProfileConfiguration::getCertificateValidity), "P365D")
                        .set(field(SignatureQualifierProfileConfiguration::getCertificateValidityOffset), "P0D")
                        .set(field(SignatureQualifierProfileConfiguration::getCsrSignatureAlgorithm), "SHA256WithRSA")
                        .set(field(SignatureQualifierProfileConfiguration::getUsernamePattern), "$[UserInfo.name]")
                        .set(field(SignatureQualifierProfileConfiguration::getDn),
                             new NamePattern("CN=$[UserInfo.name]", List.of("CN"))
                        ).set(field(SignatureQualifierProfileConfiguration::getSan),
                              new NamePattern("$[UserInfo.username]", List.of())
                );
    }

}