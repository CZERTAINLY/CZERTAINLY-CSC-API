package com.czertainly.csc.providers;

import com.czertainly.csc.common.OptionalPatternReplacer;
import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public class PatternDnProvider implements DistinguishedNameProvider {

    private final OptionalPatternReplacer patternReplacer;

    public PatternDnProvider(String dnPattern, List<String> requiredComponents) {
        if (dnPattern == null || dnPattern.isBlank()) {
            throw new ApplicationConfigurationException("Distinguished Name pattern is not set.");
        }
        if (requiredComponents == null || requiredComponents.isEmpty()) {
            throw new ApplicationConfigurationException("Distinguished Name required components are not set.");
        }
        this.patternReplacer = new OptionalPatternReplacer(dnPattern, requiredComponents,
                                                           "Distinguished Name Provider"
        );
    }

    @Override
    public Result<String, TextError> getDistinguishedName(Supplier<Map<String, String>> keyValueSource) {
        try {
            return Result.success(patternReplacer.replacePattern(keyValueSource));
        } catch (Exception e) {
            return Result.error(
                    TextError.of("Could not create Distinguished Name based on the provided pattern.", e.getMessage()));
        }
    }
}
