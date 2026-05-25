package com.otilm.csc.providers;

import com.otilm.csc.common.PatternReplacer;
import com.otilm.csc.common.exceptions.ApplicationConfigurationException;
import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;

import java.util.Map;
import java.util.function.Supplier;

public class PatternUsernameProvider implements UsernameProvider {

    private final PatternReplacer patternReplacer;

    public PatternUsernameProvider(String pattern) {
        if (pattern == null || pattern.isBlank()) {
            throw new ApplicationConfigurationException("Username pattern is not set.");
        }
        this.patternReplacer = new PatternReplacer(pattern, "Username Provider");
    }

    @Override
    public Result<String, TextError> getUsername(Supplier<Map<String, String>> keyValueSource) {
        try {
            return Result.success(patternReplacer.replacePattern(keyValueSource));
        } catch (Exception e) {
            return Result.error(
                    TextError.of("Could not create Username based on the provided pattern.", e.getMessage()));
        }
    }
}
