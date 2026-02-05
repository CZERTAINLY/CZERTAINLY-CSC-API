package com.czertainly.csc.signing.configuration.loader;

import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.configuration.keypools.KeyPoolProfile;
import com.czertainly.csc.configuration.keypools.KeyPoolProfilesConfiguration;
import com.czertainly.csc.signing.configuration.*;
import com.czertainly.csc.signing.filter.Worker;
import com.czertainly.csc.utils.configuration.CscConfigurationBuilder;
import com.czertainly.csc.utils.configuration.KeyPoolProfileBuilder;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.czertainly.csc.utils.assertions.CollectionAssertions.assertContainsExactlyInAnyOrder;
import static org.junit.jupiter.api.Assertions.*;

class WorkerConfigurationLoaderTest {

    @TempDir
    static File tempDir;

    private WorkerConfigurationLoader workerConfigurationLoader;

    @Test
    void getWorkersValid() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_validWorkers.yml");

        // when
        List<WorkerWithCapabilities> workers = workerConfigurationLoader.getWorkers();

        // then
        assertNotNull(workers);
        assertEquals(1, workers.size());
        WorkerWithCapabilities workerWithCapabilities = workers.getFirst();
        Worker worker = workerWithCapabilities.worker();
        assertEquals("XAdES-Baseline-B", worker.workerName());
        assertEquals(201, worker.workerId());
        assertEquals(1, worker.cryptoToken().id());
        assertEquals("SigningToken01", worker.cryptoToken().name());
        WorkerCapabilities capabilities = workerWithCapabilities.capabilities();
        assertContainsExactlyInAnyOrder(List.of("eu_eidas_qes", "eu_eidas_aes"), capabilities.signatureQualifiers());
        assertEquals(SignatureFormat.XAdES, capabilities.signatureFormat());
        assertEquals(ConformanceLevel.AdES_B_B, capabilities.conformanceLevel());
        assertEquals(SignaturePackaging.DETACHED, capabilities.signaturePackaging());
        assertContainsExactlyInAnyOrder(List.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA"),
                                        capabilities.supportedSignatureAlgorithms()
        );
        assertFalse(capabilities.returnsValidationInfo());
    }

    @Test
    void getWorkersMissingName() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingName.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. Worker is missing a 'name' property.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersMissingId() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingId.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing an 'id' property.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersMissingCryptoToken() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingCryptoToken.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'cryptoToken' property.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersUnknownCryptoToken() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_unknownCryptoToken.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' references an unknown CryptoToken 'SigningToken01'.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersMissingSignatureQualifiers() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingSignatureQualifiers.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'signatureQualifiers' capability.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersMissingSignatureFormat() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingSignatureFormat.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'signatureFormat' capability.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersMissingConformanceLevel() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingConformanceLevel.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'conformanceLevel' capability.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersMissingSignaturePackaging() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingSignaturePackaging.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'signaturePackaging' capability.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersMissingSignatureAlgorithms() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingSignatureAlgorithms.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'signatureAlgorithms' capability.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    // CryptoToken validations
    @Test
    void constructorShouldFailWhenCryptoTokenMissingName() throws Exception {
        // when
        Executable cb = () -> createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_cryptoTokenMissingName.yml");

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. CryptoToken is missing a 'name' property.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void constructorShouldFailWhenCryptoTokenMissingId() throws Exception {
        // when
        Executable cb = () -> createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_cryptoTokenMissingId.yml");

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. CryptoToken 'SigningToken01' is missing an 'id' property.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void constructorShouldFailWhenCryptoTokenReferencesUnknownKeyPoolProfile() throws Exception {
        // given
        File workersFile = copyResourceToFileSystem(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_unknownKeyPoolProfile.yml");
        // Create KeyPoolProfilesConfiguration with a different profile name (not "unknown-pool")
        KeyPoolProfile keyPoolProfile = KeyPoolProfileBuilder.create()
                                                             .withName("test-pool")
                                                             .build();
        KeyPoolProfilesConfiguration keyPoolProfilesConfiguration = new KeyPoolProfilesConfiguration(
                List.of(keyPoolProfile));

        // when
        Executable cb = () -> new WorkerConfigurationLoader(
                new CscConfigurationBuilder().withWorkerConfigurationFile(workersFile.getAbsolutePath()).build(),
                keyPoolProfilesConfiguration
        );

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. CryptoToken 'SigningToken01' references an unknown KeyPoolProfile 'unknown-pool'.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void constructorShouldFailWhenWorkerConfigurationFileNotFound() {
        // when
        Executable cb = () -> new WorkerConfigurationLoader(
                new CscConfigurationBuilder().withWorkerConfigurationFile("/non/existent/file.yml").build(),
                new KeyPoolProfilesConfiguration(List.of())
        );

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration file not found.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    // RAW Signer
    @Test
    void getWorkersShouldReturnRawSignerCapabilitiesWhenDocumentTypeIsRaw() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_rawSigner.yml");

        // when
        List<WorkerWithCapabilities> workers = workerConfigurationLoader.getWorkers();

        // then
        assertNotNull(workers);
        assertEquals(1, workers.size());
        WorkerWithCapabilities workerWithCapabilities = workers.getFirst();
        Worker worker = workerWithCapabilities.worker();
        assertEquals("RawSigner", worker.workerName());
        assertEquals(301, worker.workerId());

        WorkerCapabilities capabilities = workerWithCapabilities.capabilities();
        assertContainsExactlyInAnyOrder(List.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA"),
                                        capabilities.supportedSignatureAlgorithms()
        );
        assertContainsExactlyInAnyOrder(
                List.of(DocumentType.RAW.name()),
                capabilities.documentTypes().stream().map(Enum::name).collect(Collectors.toList())
        );
        // RAW signer should have null for document-specific capabilities
        assertEquals(0, capabilities.signatureQualifiers().size());
        assertNull(capabilities.signatureFormat());
        assertNull(capabilities.conformanceLevel());
        assertNull(capabilities.signaturePackaging());
        assertFalse(capabilities.returnsValidationInfo());
    }

    @Test
    void getWorkersShouldFailWhenRawSignerMissingSignatureAlgorithms() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_rawSignerMissingAlgorithms.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker configuration is not valid. Worker 'RawSigner' is missing a 'signatureAlgorithms' capability.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    // ========== Invalid Capability Values Tests ==========

    @Test
    void getWorkersShouldFailWhenInvalidSignatureFormat() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_invalidSignatureFormat.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker 'XAdES-Baseline-B' has an invalid capability.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersShouldFailWhenInvalidConformanceLevel() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_invalidConformanceLevel.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker 'XAdES-Baseline-B' has an invalid capability.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersShouldFailWhenInvalidSignaturePackaging() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_invalidSignaturePackaging.yml");

        // when
        Executable cb = () -> workerConfigurationLoader.getWorkers();

        // then
        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
        String expectedMessage = "Worker 'XAdES-Baseline-B' has an invalid capability.";
        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    @Test
    void getWorkersShouldReturnEmptyListWhenNoSigners() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_emptySigners.yml");

        // when
        List<WorkerWithCapabilities> workers = workerConfigurationLoader.getWorkers();

        // then
        assertNotNull(workers);
        assertTrue(workers.isEmpty());
    }

    @Test
    void getWorkersShouldHandleMultipleValidWorkers() throws Exception {
        // given
        workerConfigurationLoader = createLoader(
                "com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_multipleWorkers.yml");

        // when
        List<WorkerWithCapabilities> workers = workerConfigurationLoader.getWorkers();

        // then
        assertNotNull(workers);
        assertEquals(3, workers.size());

        // Verify first worker (XAdES)
        WorkerWithCapabilities xadesWorker = workers.get(0);
        assertEquals("XAdES-Baseline-B", xadesWorker.worker().workerName());
        assertEquals(201, xadesWorker.worker().workerId());
        assertEquals("SigningToken01", xadesWorker.worker().cryptoToken().name());
        assertEquals(SignatureFormat.XAdES, xadesWorker.capabilities().signatureFormat());

        // Verify second worker (PAdES)
        WorkerWithCapabilities padesWorker = workers.get(1);
        assertEquals("PAdES-Baseline-B", padesWorker.worker().workerName());
        assertEquals(202, padesWorker.worker().workerId());
        assertEquals("SigningToken02", padesWorker.worker().cryptoToken().name());
        assertEquals(SignatureFormat.PAdES, padesWorker.capabilities().signatureFormat());
        assertTrue(padesWorker.capabilities().returnsValidationInfo());

        // Verify third worker (RAW)
        WorkerWithCapabilities rawWorker = workers.get(2);
        assertEquals("RawSigner", rawWorker.worker().workerName());
        assertEquals(301, rawWorker.worker().workerId());
        assertEquals("SigningToken01", rawWorker.worker().cryptoToken().name());
        assertTrue(rawWorker.capabilities().documentTypes()
                            .contains(com.czertainly.csc.signing.configuration.DocumentType.RAW));
    }

    private WorkerConfigurationLoader createLoader(String workersYmlResource) throws Exception {
        File workersFile = copyResourceToFileSystem(workersYmlResource);

        List<String> keyPoolProfileNames = getKeyPoolProfileNames(workersFile);

        List<KeyPoolProfile> keyPoolProfiles = keyPoolProfileNames.stream()
                                                                  .map(name -> KeyPoolProfileBuilder.create()
                                                                                                    .withName(name)
                                                                                                    .build())
                                                                  .collect(Collectors.toList());

        KeyPoolProfilesConfiguration keyPoolProfilesConfiguration = new KeyPoolProfilesConfiguration(keyPoolProfiles);

        return new WorkerConfigurationLoader(
                new CscConfigurationBuilder().withWorkerConfigurationFile(workersFile.getAbsolutePath()).build(),
                keyPoolProfilesConfiguration
        );
    }

    private File copyResourceToFileSystem(String resourceName) throws Exception {
        File file = new File(tempDir, UUID.randomUUID() + ".yml");
        ClassLoader classLoader = WorkerConfigurationLoaderTest.class.getClassLoader();
        try (InputStream is = classLoader.getResourceAsStream(resourceName)) {
            try (OutputStream os = new FileOutputStream(file)) {
                byte[] buffer = new byte[1024];
                int length;
                while ((length = is.read(buffer)) > 0) {
                    os.write(buffer, 0, length);
                }
            }
        }
        return file;
    }

    private static @NotNull List<String> getKeyPoolProfileNames(File workersFile) throws IOException {
        // Parse the YAML file to extract key pool profile names
        Yaml yaml = new Yaml(new Constructor(WorkerConfigurationFile.class, new LoaderOptions()));
        WorkerConfigurationFile config;
        try (BufferedReader reader = new BufferedReader(new FileReader(workersFile))) {
            config = yaml.load(reader);
        }

        // Extract all unique key pool profile names from crypto tokens
        List<String> keyPoolProfileNames = new ArrayList<>();
        if (config.getCryptoTokens() != null) {
            keyPoolProfileNames = config.getCryptoTokens().stream()
                                        .filter(token -> token.getKeyPoolProfiles() != null)
                                        .flatMap(token -> token.getKeyPoolProfiles().stream())
                                        .distinct()
                                        .collect(Collectors.toList());
        }
        return keyPoolProfileNames;
    }
}
