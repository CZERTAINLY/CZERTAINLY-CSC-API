package com.czertainly.csc.signing.configuration.loader;

import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.configuration.csc.CscConfiguration;
import com.czertainly.csc.configuration.keypools.KeyPoolProfile;
import com.czertainly.csc.configuration.keypools.KeyPoolProfilesConfiguration;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.signing.configuration.*;
import com.czertainly.csc.signing.filter.Worker;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class WorkerConfigurationLoader {

    private final WorkerConfigurationFile configuration;
    private final Map<String, KeyPoolProfile> keyPoolMap;

    public WorkerConfigurationLoader(CscConfiguration cscConfiguration,
                                     KeyPoolProfilesConfiguration keyPoolProfilesConfiguration
    ) {
        this.keyPoolMap = keyPoolProfilesConfiguration.keyPoolProfiles()
                                                      .stream()
                                                      .collect(Collectors.toMap(KeyPoolProfile::name,
                                                                                Function.identity()
                                                      ));
        Yaml yaml = new Yaml(new Constructor(WorkerConfigurationFile.class, new LoaderOptions()));
        try {
            configuration = yaml.load(new BufferedReader(new FileReader(cscConfiguration.workerConfigurationFile())));
            getCryptoTokenMap(configuration.getCryptoTokens());
        } catch (FileNotFoundException e) {
            throw new ApplicationConfigurationException("Worker configuration file not found.", e);
        }
    }

    public List<WorkerWithCapabilities> getWorkers() {
        List<WorkerWithCapabilities> workersWithCapabilities = new ArrayList<>();

        Map<String, CryptoToken> cryptoTokenMap = getCryptoTokenMap(configuration.getCryptoTokens());
        List<WorkerConfiguration> workerConfigurations = configuration.getSigners() != null ? configuration.getSigners() : List.of();
        for (WorkerConfiguration workerConfiguration : workerConfigurations) {
            String workerName = workerConfiguration.getName();
            if (workerName == null) {
                throw new ApplicationConfigurationException(
                        "Worker configuration is not valid. Worker is missing a 'name' property.");
            }
            int workerId = workerConfiguration.getId();
            if (workerId == -1) {
                throw new ApplicationConfigurationException(
                        "Worker configuration is not valid. Worker '" + workerName + "' is missing an 'id' property.");
            }
            String tokenName = workerConfiguration.getCryptoToken();
            if (tokenName == null) {
                throw new ApplicationConfigurationException(
                        "Worker configuration is not valid. Worker '" + workerName + "' is missing a 'cryptoToken' property.");
            }
            CryptoToken cryptoToken = cryptoTokenMap.get(tokenName);
            if (cryptoToken == null) {
                throw new ApplicationConfigurationException(
                        "Worker configuration is not valid. Worker '" + workerName + "' references an unknown CryptoToken '" + tokenName + "'.");
            }

            WorkerCapabilities capabilities;
            if (workerConfiguration.getCapabilities()
                                   .getDocumentTypes() != null && workerConfiguration.getCapabilities()
                                                                                     .getDocumentTypes()
                                                                                     .contains(DocumentType.RAW)) {
                capabilities = getRawSignerCapabilities(workerConfiguration.getCapabilities(), workerName);
            } else {
                capabilities = getDocumentSignerCapabilities(workerConfiguration.getCapabilities(), workerName);
            }

            Worker worker = new Worker(workerName, workerId, cryptoToken);

            workersWithCapabilities.add(new WorkerWithCapabilities(worker, capabilities));

        }
        return workersWithCapabilities;
    }

    private WorkerCapabilities getDocumentSignerCapabilities(WorkerCapabilitiesConfiguration capabilitiesConfiguration,
                                                             String workerName
    ) {
        List<String> signatureQualifiers = capabilitiesConfiguration.getSignatureQualifiers();
        if (signatureQualifiers == null) {
            throw new ApplicationConfigurationException(
                    "Worker configuration is not valid. Worker '" + workerName + "' is missing a 'signatureQualifiers' capability.");
        }
        String signatureFormat = capabilitiesConfiguration.getSignatureFormat();
        if (signatureFormat == null) {
            throw new ApplicationConfigurationException(
                    "Worker configuration is not valid. Worker '" + workerName + "' is missing a 'signatureFormat' capability.");
        }

        String conformanceLevel = capabilitiesConfiguration.getConformanceLevel();
        if (conformanceLevel == null) {
            throw new ApplicationConfigurationException(
                    "Worker configuration is not valid. Worker '" + workerName + "' is missing a 'conformanceLevel' capability.");
        }

        String signaturePackaging = capabilitiesConfiguration.getSignaturePackaging();
        if (signaturePackaging == null) {
            throw new ApplicationConfigurationException(
                    "Worker configuration is not valid. Worker '" + workerName + "' is missing a 'signaturePackaging' capability.");
        }

        List<String> supportedSignatureAlgorithms = capabilitiesConfiguration.getSignatureAlgorithms();
        if (supportedSignatureAlgorithms == null) {
            throw new ApplicationConfigurationException(
                    "Worker configuration is not valid. Worker '" + workerName + "' is missing a 'signatureAlgorithms' capability."
            );
        }

        boolean returnsValidationInfo = capabilitiesConfiguration.isReturnsValidationInfo();

        if (capabilitiesConfiguration.getDocumentTypes() == null || capabilitiesConfiguration.getDocumentTypes()
                                                                                             .isEmpty()) {
            capabilitiesConfiguration.setDocumentTypes(List.of(DocumentType.HASH));
        }

        try {
            return new WorkerCapabilities(
                    signatureQualifiers, SignatureFormat.fromString(signatureFormat),
                    ConformanceLevel.fromString(conformanceLevel),
                    SignaturePackaging.fromString(signaturePackaging),
                    supportedSignatureAlgorithms, returnsValidationInfo,
                    capabilitiesConfiguration.getDocumentTypes()
            );
        } catch (IllegalArgumentException e) {
            throw new ApplicationConfigurationException("Worker '" + workerName + "' has an invalid capability.", e);
        }
    }

    private WorkerCapabilities getRawSignerCapabilities(WorkerCapabilitiesConfiguration capabilitiesConfiguration,
                                                        String workerName
    ) {
        List<String> supportedSignatureAlgorithms = capabilitiesConfiguration.getSignatureAlgorithms();
        if (supportedSignatureAlgorithms == null) {
            throw new ApplicationConfigurationException(
                    "Worker configuration is not valid. Worker '" + workerName + "' is missing a 'signatureAlgorithms' capability."
            );
        }

        try {
            return new WorkerCapabilities(
                    null, null, null, null, supportedSignatureAlgorithms, false, List.of(DocumentType.RAW)
            );
        } catch (IllegalArgumentException e) {
            throw new ApplicationConfigurationException("Worker '" + workerName + "' has an invalid capability.", e);
        }
    }

    private Map<String, CryptoToken> getCryptoTokenMap(List<CryptoTokenDefinition> cryptoTokenConfigurations) {
        Map<String, CryptoToken> map = new HashMap<>();
        for (CryptoTokenDefinition cryptoTokenConfiguration : cryptoTokenConfigurations) {
            String tokenName = cryptoTokenConfiguration.getName();
            if (tokenName == null) {
                throw new ApplicationConfigurationException(
                        "Worker configuration is not valid. CryptoToken is missing a 'name' property.");
            }
            int id = cryptoTokenConfiguration.getId();
            if (id == -1) {
                throw new ApplicationConfigurationException(
                        "Worker configuration is not valid. CryptoToken '" + tokenName + "' is missing an 'id' property.");
            }

            List<KeyPoolProfile> keyPoolProfiles = new ArrayList<>();
            for (String keyPoolProfileName : cryptoTokenConfiguration.getKeyPoolProfiles()) {
                KeyPoolProfile keyPoolProfile = keyPoolMap.get(keyPoolProfileName);
                if (keyPoolProfile == null) {
                    throw new ApplicationConfigurationException(
                            "Worker configuration is not valid. CryptoToken '" + tokenName + "' references an unknown" +
                                    " KeyPoolProfile '" + keyPoolProfileName + "'.");
                }
                keyPoolProfiles.add(keyPoolProfile);
            }

            map.put(tokenName, new CryptoToken(tokenName, id, keyPoolProfiles));
        }
        return map;
    }

}
