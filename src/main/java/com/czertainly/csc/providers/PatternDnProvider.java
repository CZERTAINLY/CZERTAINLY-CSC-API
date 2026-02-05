package com.czertainly.csc.providers;

import com.czertainly.csc.common.OptionalPatternReplacer;
import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.providers.sanitization.DnAndSanSanitizer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public class PatternDnProvider implements DistinguishedNameProvider {

    private final OptionalPatternReplacer patternReplacer;
    private final DnAndSanSanitizer valueSanitizer;

    /**
     * @param dnPattern the DN pattern with placeholders
     * @param requiredComponents list of required DN components
     * @param valueSanitizer function to sanitize individual component values (can be null)
     */
    public PatternDnProvider(String dnPattern,
                            List<String> requiredComponents,
                            DnAndSanSanitizer valueSanitizer) {
        if (dnPattern == null || dnPattern.isBlank()) {
            throw new ApplicationConfigurationException("Distinguished Name pattern is not set.");
        }
        if (requiredComponents == null || requiredComponents.isEmpty()) {
            throw new ApplicationConfigurationException("Distinguished Name required components are not set.");
        }
        this.patternReplacer = new OptionalPatternReplacer(dnPattern, requiredComponents,
                                                           "Distinguished Name Provider"
        );
        this.valueSanitizer = valueSanitizer;
    }

    @Override
    public Result<String, TextError> getDistinguishedName(Supplier<Map<String, String>> keyValueSource) {
        try {
            // Eagerly resolve and sanitize values once to avoid repeated supplier evaluation
            Map<String, String> values = keyValueSource.get();
            if (valueSanitizer != null) {
                Map<String, String> sanitized = new HashMap<>();
                values.forEach((k, v) -> sanitized.put(k, valueSanitizer.escapeValue(v)));
                values = sanitized;
            }
            Map<String, String> resolved = values;
            Supplier<Map<String, String>> sanitizedSource = () -> resolved;

            String dn = patternReplacer.replacePattern(sanitizedSource);

            return Result.success(dn);
        } catch (Exception e) {
            return Result.error(
                    TextError.of("Could not create Distinguished Name based on the provided pattern.", e.getMessage()));
        }
    }
}
