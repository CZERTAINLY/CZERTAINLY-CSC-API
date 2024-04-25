package com.czertainly.signserver.csc.api.signhash;

import java.util.List;

public class SignHashResponseDto {
    private final List<String> signatures;

    public SignHashResponseDto(List<String> signatures) {
        this.signatures = signatures;
    }

    public List<String> getSignatures() {
        return signatures;
    }
}
