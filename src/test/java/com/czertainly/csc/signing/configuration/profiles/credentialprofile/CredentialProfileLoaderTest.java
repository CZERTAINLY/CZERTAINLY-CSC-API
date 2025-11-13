package com.czertainly.csc.signing.configuration.profiles.credentialprofile;

import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.configuration.csc.CscConfiguration;
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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialProfileLoaderTest {

    Path configurationDirectory = Files.createTempDirectory("configs");
    CscConfiguration cscConfiguration = new CscConfigurationBuilder()
            .withProfilesConfigurationDirectory(configurationDirectory.toString())
            .build();

    CredentialProfileLoaderTest() throws IOException {}

    @Test
    void loadCredentialProfilesCanLoadEmptyProfilesConfiguration() {
        // given
        File config = prepareConfigurationFile(List.of());

        // when
        CredentialProfileLoader loader = new CredentialProfileLoader(
                cscConfiguration,
                config.getName()
        );

        // then
        assertTrue(loader.getProfiles().isEmpty());
    }

    @Test
    void loadCredentialProfilesCanLoadProfilesConfiguration() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration().create(),
                aCredentialProfileConfiguration().create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        CredentialProfileLoader loader = new CredentialProfileLoader(
                cscConfiguration,
                config.getName()
        );

        // then
        assertEquals(2, loader.getProfiles().size());
    }

    @Test
    void loadCredentialProfilesLoadsConfigurationCorrectly() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration().create());
        File config = prepareConfigurationFile(profiles);

        // when
        CredentialProfileLoader loader = new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertEquals(1, loader.getProfiles().size());
        CredentialProfile profile = loader.getProfiles().getFirst();
        assertEquals("profile1", profile.getName());
        assertEquals("aCA", profile.getCertificateAuthority());
        assertEquals("CertProfile1", profile.getCertificateProfileName());
        assertEquals("EndEntityProfile1", profile.getEndEntityProfileName());
        assertEquals(Duration.ofDays(365), profile.getCertificateValidity());
        assertEquals(Duration.ZERO, profile.getCertificateValidityOffset());
        assertEquals("RSA", profile.getKeyAlgorithm());
        assertEquals("2048", profile.getKeySpecification());
        assertEquals("SHA256WithRSA", profile.getCsrSignatureAlgorithm());
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
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, configurationFile);

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "does not exist",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfConfigurationFileIsEmpty() throws IOException {
        // given
        File config = File.createTempFile("credential-profiles-ejbca", "yml", configurationDirectory.toFile());


        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Configuration file is empty",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfConfigurationFileIsInvalid() throws IOException {
        // given
        File config = File.createTempFile("credential-profiles-ejbca", "yml", configurationDirectory.toFile());
        try (FileWriter writer = new FileWriter(config)) {
            writer.write("invalid yaml");
        }

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Failed to parse configuration file.",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingName() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getName), null)
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Missing value for 'name' property",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingCaName() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getCaName), null)
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Missing value for 'caName' property",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingCertificateProfileName() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getCertificateProfileName), null)
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Missing value for 'certificateProfileName' property",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingEndEntityProfileName() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getEndEntityProfileName), null)
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Missing value for 'endEntityProfileName' property",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingCertificateValidity() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getCertificateValidity), null)
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Missing value for 'certificateValidity' property",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileHasInvalidCertificateValidity() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getCertificateValidity), "not-ISO-8601")
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Invalid duration format for 'certificateValidity'",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingCertificateValidityOffset() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getCertificateValidityOffset), null)
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Missing value for 'certificateValidityOffset' property",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingKeyAlgorithm() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getKeyAlgorithm), null)
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Missing value for 'keyAlgorithm' property",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingKeySpecification() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getKeySpecification), null)
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Missing value for 'keySpecification' property",
                ex
        );
    }

    @Test
    void loadCredentialProfilesThrowsExceptionIfProfileIsMissingCsrSignatureAlgorithm() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getCsrSignatureAlgorithm), null)
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "Missing value for 'csrSignatureAlgorithm' property",
                ex
        );
    }

    @Test
    void loadCredentialProfilesExceptionContainsNameOfTheInvalidProfile() {
        // given
        List<CredentialProfileConfiguration> profiles = List.of(
                aCredentialProfileConfiguration()
                        .set(field(CredentialProfileConfiguration::getName), "myProfile")
                        .set(field(CredentialProfileConfiguration::getCertificateProfileName), null)
                        .create()
        );
        File config = prepareConfigurationFile(profiles);

        // when
        Executable ex = () -> new CredentialProfileLoader(cscConfiguration, config.getName());

        // then
        assertThrowsAndMessageContains(
                ApplicationConfigurationException.class,
                "myProfile",
                ex
        );
    }


    private File prepareConfigurationFile(List<CredentialProfileConfiguration> profiles) {
        try {
            Path f = Files.createTempFile(configurationDirectory, "credential-profiles-ejbca", ".yml");
            DumperOptions options = new DumperOptions();
            options.setIndent(2);
            options.setPrettyFlow(true);
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);

            Representer representer = new Representer(options);
            representer.addClassTag(CredentialProfilesConfigurationFile.class, Tag.MAP);
            Yaml yaml = new Yaml(representer, options);

            CredentialProfilesConfigurationFile configuration = new CredentialProfilesConfigurationFile();
            configuration.setProfiles(profiles);
            try (FileWriter writer = new FileWriter(f.toFile())) {
                yaml.dump(configuration, writer);
            }
            return f.toFile();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    private InstancioApi<CredentialProfileConfiguration> aCredentialProfileConfiguration() {
        return Instancio.of(CredentialProfileConfiguration.class)
                        .set(field(CredentialProfileConfiguration::getName), "profile1")
                        .set(field(CredentialProfileConfiguration::getCaName), "aCA")
                        .set(field(CredentialProfileConfiguration::getCertificateProfileName), "CertProfile1")
                        .set(field(CredentialProfileConfiguration::getEndEntityProfileName), "EndEntityProfile1")
                        .set(field(CredentialProfileConfiguration::getCertificateValidity), "P365D")
                        .set(field(CredentialProfileConfiguration::getCertificateValidityOffset), "P0D")
                        .set(field(CredentialProfileConfiguration::getKeyAlgorithm), "RSA")
                        .set(field(CredentialProfileConfiguration::getKeySpecification), "2048")
                        .set(field(CredentialProfileConfiguration::getCsrSignatureAlgorithm), "SHA256WithRSA");
    }

}