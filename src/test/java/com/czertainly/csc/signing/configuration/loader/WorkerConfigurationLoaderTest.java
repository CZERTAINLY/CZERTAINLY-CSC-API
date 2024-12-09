//package com.czertainly.csc.signing.configuration.loader;
//
//import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
//import com.czertainly.csc.signing.configuration.ConformanceLevel;
//import com.czertainly.csc.signing.configuration.SignatureFormat;
//import com.czertainly.csc.signing.configuration.SignaturePackaging;
//import com.czertainly.csc.signing.configuration.WorkerCapabilities;
//import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
//import com.czertainly.csc.signing.filter.Worker;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.function.Executable;
//import org.junit.jupiter.api.io.TempDir;
//
//import java.io.File;
//import java.io.FileOutputStream;
//import java.io.InputStream;
//import java.io.OutputStream;
//import java.util.List;
//import java.util.UUID;
//
//import static com.czertainly.csc.utils.assertions.CollectionAssertions.assertContainsExactlyInAnyOrder;
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.junit.jupiter.api.Assertions.assertFalse;
//import static org.junit.jupiter.api.Assertions.assertNotNull;
//import static org.junit.jupiter.api.Assertions.assertThrows;
//import static org.junit.jupiter.api.Assertions.assertTrue;
//
//class WorkerConfigurationLoaderTest {
//
//    @TempDir
//    static File tempDir;
//
//    private WorkerConfigurationLoader workerConfigurationLoader;
//
//    @Test
//    void getWorkersValid() throws Exception {
//        // given
//        File validWorker = copyResourceToFileSystem("com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_validWorkers.yml");
//        workerConfigurationLoader = new WorkerConfigurationLoader(validWorker.getAbsolutePath());
//
//        // when
//        List<WorkerWithCapabilities> workers = workerConfigurationLoader.getWorkers();
//
//        // then
//        assertNotNull(workers);
//        assertEquals(1, workers.size());
//        WorkerWithCapabilities workerWithCapabilities = workers.getFirst();
//        Worker worker = workerWithCapabilities.worker();
//        assertEquals("XAdES-Baseline-B", worker.workerName());
//        assertEquals(201, worker.workerId());
//        assertEquals(1, worker.cryptoToken().id());
//        assertEquals("SigningToken01", worker.cryptoToken().name());
//        WorkerCapabilities capabilities = workerWithCapabilities.capabilities();
//        assertContainsExactlyInAnyOrder(List.of("eu_eidas_qes", "eu_eidas_aes"), capabilities.signatureQualifiers());
//        assertEquals(SignatureFormat.XAdES, capabilities.signatureFormat());
//        assertEquals(ConformanceLevel.AdES_B_B, capabilities.conformanceLevel());
//        assertEquals(SignaturePackaging.DETACHED, capabilities.signaturePackaging());
//        assertContainsExactlyInAnyOrder(List.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA"), capabilities.supportedSignatureAlgorithms());
//        assertFalse(capabilities.returnsValidationInfo());
//    }
//
//    @Test
//    void getWorkersMissingName() throws Exception {
//        // given
//        File missingNameWorkers = copyResourceToFileSystem("com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingName.yml");
//        workerConfigurationLoader = new WorkerConfigurationLoader(missingNameWorkers.getAbsolutePath());
//
//        // when
//        Executable cb = () -> workerConfigurationLoader.getWorkers();
//
//        // then
//        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
//        String expectedMessage = "Worker configuration is not valid. Worker is missing a 'name' property.";
//        assertTrue(exception.getMessage().contains(expectedMessage));
//    }
//
//    @Test
//    void getWorkersMissingId() throws Exception {
//        // given
//        File missingIdWorkers = copyResourceToFileSystem("com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingId.yml");
//        workerConfigurationLoader = new WorkerConfigurationLoader(missingIdWorkers.getAbsolutePath());
//
//        // when
//        Executable cb = () -> workerConfigurationLoader.getWorkers();
//
//        // then
//        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
//        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing an 'id' property.";
//        assertTrue(exception.getMessage().contains(expectedMessage));
//    }
//
//    @Test
//    void getWorkersMissingCryptoToken() throws Exception {
//        // given
//        File missingCryptoToken = copyResourceToFileSystem("com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingCryptoToken.yml");
//        workerConfigurationLoader = new WorkerConfigurationLoader(missingCryptoToken.getAbsolutePath());
//
//        // when
//        Executable cb = () -> workerConfigurationLoader.getWorkers();
//
//        // then
//        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
//        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'cryptoToken' property.";
//        assertTrue(exception.getMessage().contains(expectedMessage));
//    }
//
//    @Test
//    void getWorkersUnknownCryptoToken() throws Exception {
//        // given
//        File unknownCryptoTokenWorkers = copyResourceToFileSystem("com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_unknownCryptoToken.yml");
//        workerConfigurationLoader = new WorkerConfigurationLoader(unknownCryptoTokenWorkers.getAbsolutePath());
//
//        // when
//        Executable cb = () -> workerConfigurationLoader.getWorkers();
//
//        // then
//        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
//        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' references an unknown CryptoToken 'SigningToken01'.";
//        assertTrue(exception.getMessage().contains(expectedMessage));
//    }
//
//    @Test
//    void getWorkersMissingSignatureQualifiers() throws Exception {
//        // given
//        File missingSignatureQualifiers = copyResourceToFileSystem("com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingSignatureQualifiers.yml");
//        workerConfigurationLoader = new WorkerConfigurationLoader(missingSignatureQualifiers.getAbsolutePath());
//
//        // when
//        Executable cb = () -> workerConfigurationLoader.getWorkers();
//
//        // then
//        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
//        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'signatureQualifiers' capability.";
//        assertTrue(exception.getMessage().contains(expectedMessage));
//    }
//
//    @Test
//    void getWorkersMissingSignatureFormat() throws Exception {
//        // given
//        File missingSignatureFormat = copyResourceToFileSystem("com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingSignatureFormat.yml");
//        workerConfigurationLoader = new WorkerConfigurationLoader(missingSignatureFormat.getAbsolutePath());
//
//        // when
//        Executable cb = () -> workerConfigurationLoader.getWorkers();
//
//        // then
//        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
//        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'signatureFormat' capability.";
//        assertTrue(exception.getMessage().contains(expectedMessage));
//    }
//
//    @Test
//    void getWorkersMissingConformanceLevel() throws Exception {
//        // given
//        File missingConformanceLevel = copyResourceToFileSystem("com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingConformanceLevel.yml");
//        workerConfigurationLoader = new WorkerConfigurationLoader(missingConformanceLevel.getAbsolutePath());
//
//        // when
//        Executable cb = () -> workerConfigurationLoader.getWorkers();
//
//        // then
//        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
//        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'conformanceLevel' capability.";
//        assertTrue(exception.getMessage().contains(expectedMessage));
//    }
//
//    @Test
//    void getWorkersMissingSignaturePackaging() throws Exception {
//        // given
//        File missingSignaturePackaging = copyResourceToFileSystem("com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingSignaturePackaging.yml");
//        workerConfigurationLoader = new WorkerConfigurationLoader(missingSignaturePackaging.getAbsolutePath());
//
//        // when
//        Executable cb = () -> workerConfigurationLoader.getWorkers();
//
//        // then
//        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
//        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'signaturePackaging' capability.";
//        assertTrue(exception.getMessage().contains(expectedMessage));
//    }
//
//    @Test
//    void getWorkersMissingSignatureAlgorithms() throws Exception {
//        // given
//        File missingSignatureAlgorithms = copyResourceToFileSystem("com/czertainly/csc/signing/configuration/loader/WorkerConfigurationLoaderTest_missingSignatureAlgorithms.yml");
//        workerConfigurationLoader = new WorkerConfigurationLoader(missingSignatureAlgorithms.getAbsolutePath());
//
//        // when
//        Executable cb = () -> workerConfigurationLoader.getWorkers();
//
//        // then
//        Exception exception = assertThrows(ApplicationConfigurationException.class, cb);
//        String expectedMessage = "Worker configuration is not valid. Worker 'XAdES-Baseline-B' is missing a 'signatureAlgorithms' capability.";
//        assertTrue(exception.getMessage().contains(expectedMessage));
//    }
//
//    private File copyResourceToFileSystem(String resourceName) throws Exception {
//        File file = new File(tempDir, UUID.randomUUID() + ".yml");
//        ClassLoader classLoader = WorkerConfigurationLoaderTest.class.getClassLoader();
//        try (InputStream is = classLoader.getResourceAsStream(resourceName)) {
//            try (OutputStream os = new FileOutputStream(file)) {
//                byte[] buffer = new byte[1024];
//                int length;
//                while ((length = is.read(buffer)) > 0) {
//                    os.write(buffer, 0, length);
//                }
//            }
//        }
//        return file;
//    }
//}
