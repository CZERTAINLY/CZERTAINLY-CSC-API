package com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile;

import java.util.List;

public class NamePattern {
    private String pattern;
    private List<String> required = List.of();

    public NamePattern() {}

    public NamePattern(String pattern, List<String> required) {
        this.pattern = pattern;
        this.required = required;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public List<String> getRequired() {
        return required;
    }

    public void setRequired(List<String> required) {
        this.required = required;
    }
}
