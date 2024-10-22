package com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile;

import java.util.List;

public class SignatureQualifierProfilesConfigurationFile {

    List<SignatureQualifierProfileConfiguration> profiles;

    public List<SignatureQualifierProfileConfiguration> getProfiles() {
        return profiles;
    }

    public void setProfiles(List<SignatureQualifierProfileConfiguration> profiles
    ) {
        this.profiles = profiles;
    }
}
