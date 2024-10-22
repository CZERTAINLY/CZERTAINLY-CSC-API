package com.czertainly.csc.signing.configuration.profiles.credentialprofile;

import java.util.List;

public class CredentialProfilesConfigurationFile {

    List<CredentialProfileConfiguration> profiles;

    public List<CredentialProfileConfiguration> getProfiles() {
        return profiles;
    }

    public void setProfiles(List<CredentialProfileConfiguration> profiles
    ) {
        this.profiles = profiles;
    }
}
