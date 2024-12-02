package com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile;

import com.czertainly.csc.providers.DistinguishedNameProvider;
import com.czertainly.csc.providers.SubjectAlternativeNameProvider;
import com.czertainly.csc.providers.UsernameProvider;
import com.czertainly.csc.signing.configuration.profiles.Profile;

import java.time.Duration;

public class SignatureQualifierProfile extends Profile {
    private final UsernameProvider usernameProvider;
    private final DistinguishedNameProvider distinguishedNameProvider;
    private final SubjectAlternativeNameProvider subjectAlternativeNameProvider;
    private final int multisign;

    public SignatureQualifierProfile(String name, String certificateAuthority, String certificateProfileName,
                                     String endEntityProfileName, Duration certificateValidity,
                                     Duration certificateValidityOffset, String csrSignatureAlgorithm,
                                     UsernameProvider usernameProvider,
                                     DistinguishedNameProvider distinguishedNameProvider,
                                     SubjectAlternativeNameProvider subjectAlternativeNameProvider,
                                     int multisign
    ) {
        super(name, certificateAuthority, certificateProfileName, endEntityProfileName, certificateValidity,
              certificateValidityOffset, csrSignatureAlgorithm
        );
        this.usernameProvider = usernameProvider;
        this.distinguishedNameProvider = distinguishedNameProvider;
        this.subjectAlternativeNameProvider = subjectAlternativeNameProvider;
        this.multisign = multisign;
    }

    public UsernameProvider getUsernameProvider() {
        return usernameProvider;
    }

    public DistinguishedNameProvider getDistinguishedNameProvider() {
        return distinguishedNameProvider;
    }

    public SubjectAlternativeNameProvider getSubjectAlternativeNameProvider() {
        return subjectAlternativeNameProvider;
    }

    public int getMultisign() {
        return multisign;
    }
}
