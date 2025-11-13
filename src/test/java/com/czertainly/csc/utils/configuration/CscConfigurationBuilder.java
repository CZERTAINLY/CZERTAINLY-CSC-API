package com.czertainly.csc.utils.configuration;

import com.czertainly.csc.configuration.csc.ConcurrencySettings;
import com.czertainly.csc.configuration.csc.CscConfiguration;
import com.czertainly.csc.configuration.csc.OneTimeKeysCleanupSettings;
import com.czertainly.csc.configuration.csc.SigningSessions;
import org.instancio.Instancio;
import org.instancio.Select;

public class CscConfigurationBuilder {

    private String name;
    private String logo;
    private String region;
    private String workerConfigurationFile;
    private String profilesConfigurationDirectory;
    private SigningSessions signingSessions;
    private OneTimeKeysCleanupSettings oneTimeKeysCleanupSettings;
    private ConcurrencySettings concurrency;

    public static CscConfiguration anCscConfiguration() {
        return Instancio.of(CscConfiguration.class)
                        .create();
    }

    public CscConfigurationBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public CscConfigurationBuilder withLogo(String logo) {
        this.logo = logo;
        return this;
    }

    public CscConfigurationBuilder withRegion(String region) {
        this.region = region;
        return this;
    }

    public CscConfigurationBuilder withWorkerConfigurationFile(String workerConfigurationFile) {
        this.workerConfigurationFile = workerConfigurationFile;
        return this;
    }

    public CscConfigurationBuilder withProfilesConfigurationDirectory(String profilesConfigurationDirectory) {
        this.profilesConfigurationDirectory = profilesConfigurationDirectory;
        return this;
    }

    public CscConfigurationBuilder withSigningSessions(SigningSessions signingSessions) {
        this.signingSessions = signingSessions;
        return this;
    }

    public CscConfigurationBuilder withOneTimeKeysCleanupSettings(OneTimeKeysCleanupSettings oneTimeKeysCleanupSettings
    ) {
        this.oneTimeKeysCleanupSettings = oneTimeKeysCleanupSettings;
        return this;
    }

    public CscConfigurationBuilder withConcurrencySettings(ConcurrencySettings concurrency) {
        this.concurrency = concurrency;
        return this;
    }

    public CscConfiguration build() {
        var partial = Instancio.of(CscConfiguration.class);
        if (name != null) {
            partial.set(Select.field(CscConfiguration::name), name);
        }

        if (logo != null) {
            partial.set(Select.field(CscConfiguration::logo), logo);
        }

        if (region != null) {
            partial.set(Select.field(CscConfiguration::region), region);
        }

        if (workerConfigurationFile != null) {
            partial.set(Select.field(CscConfiguration::workerConfigurationFile), workerConfigurationFile);
        }

        if (profilesConfigurationDirectory != null) {
            partial.set(Select.field(CscConfiguration::profilesConfigurationDirectory), profilesConfigurationDirectory);
        }

        if (signingSessions != null) {
            partial.set(Select.field(CscConfiguration::signingSessions), signingSessions);
        }

        if (oneTimeKeysCleanupSettings != null) {
            partial.set(Select.field(CscConfiguration::oneTimeKeys), oneTimeKeysCleanupSettings);
        }

        if (concurrency != null) {
            partial.set(Select.field(CscConfiguration::concurrency), concurrency);
        }

        return partial.create();
    }

}
