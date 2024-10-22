package com.czertainly.csc.providers;

import com.czertainly.csc.common.PatternReplacer;
import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;

import java.util.Map;
import java.util.function.Supplier;

public class PatternUsernameProvider implements UsernameProvider {

    private final PatternReplacer patternReplacer;

    public PatternUsernameProvider(String pattern) {
        if (pattern == null || pattern.isBlank()) {
            throw new ApplicationConfigurationException("Username pattern is not set.");
        }
        this.patternReplacer = new PatternReplacer(pattern, "Username Provider");;
    }

    @Override
    public String getUsername(Supplier<Map<String, String>> keyValueSource) {
        return patternReplacer.replacePattern(keyValueSource);
    }
}
