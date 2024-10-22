package com.czertainly.csc.providers;

import com.czertainly.csc.common.OptionalPatternReplacer;
import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;

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
        this.patternReplacer = new OptionalPatternReplacer(dnPattern, requiredComponents, "Distinguished Name Provider");
    }

    @Override
    public String getDistinguishedName(Supplier<Map<String, String>> keyValueSource) {
        return patternReplacer.replacePattern(keyValueSource);
    }
}
