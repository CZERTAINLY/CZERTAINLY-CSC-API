package com.czertainly.csc.signing.configuration.profiles;

import java.time.Duration;

public class Profile {
    private final String name;
    private final String certificateAuthority;
    private final String certificateProfileName;
    private final String endEntityProfileName;
    private final Duration certificateValidity;
    private final Duration certificateValidityOffset;

    public Profile(String name, String certificateAuthority, String certificateProfileName, String endEntityProfileName,
                   Duration certificateValidity, Duration certificateValidityOffset
    ) {
        this.name = name;
        this.certificateAuthority = certificateAuthority;
        this.certificateProfileName = certificateProfileName;
        this.endEntityProfileName = endEntityProfileName;
        this.certificateValidity = certificateValidity;
        this.certificateValidityOffset = certificateValidityOffset;
    }

    public String getName() {
        return name;
    }

    public String getCertificateAuthority() {
        return certificateAuthority;
    }

    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public Duration getCertificateValidity() {
        return certificateValidity;
    }

    public Duration getCertificateValidityOffset() {
        return certificateValidityOffset;
    }
}
