package com.czertainly.csc.providers;

import com.czertainly.csc.common.PatternReplacer;
import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.function.Supplier;

@Component
public class PatternUsernameProvider implements UsernameProvider {

    private final PatternReplacer patternReplacer;

    public PatternUsernameProvider(@Value("${caProvider.ejbca.endEntity.usernamePattern}") String pattern) {
        if (pattern.isBlank()) {
            throw new ApplicationConfigurationException("Username pattern is not set.");
        }
        this.patternReplacer = new PatternReplacer(pattern, "Username Provider");;
    }

    @Override
    public String getUsername(Supplier<Map<String, String>> keyValueSource) {
        return patternReplacer.replacePattern(keyValueSource);
    }
}
