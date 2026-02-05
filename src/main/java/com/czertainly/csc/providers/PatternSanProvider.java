package com.czertainly.csc.providers;

import com.czertainly.csc.common.OptionalPatternReplacer;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.providers.sanitization.DnAndSanSanitizer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public class PatternSanProvider implements SubjectAlternativeNameProvider {

    private final OptionalPatternReplacer patternReplacer;
    private final boolean isEmpty;
    private final DnAndSanSanitizer valueSanitizer;

    /**
     * @param pattern the SAN pattern with placeholders
     * @param requiredComponents list of required SAN components
     * @param valueSanitizer function to sanitize individual component values (can be null)
     */
    public PatternSanProvider(String pattern, List<String> requiredComponents, DnAndSanSanitizer valueSanitizer) {
        this.valueSanitizer = valueSanitizer;
        this.isEmpty = pattern == null || pattern.isBlank() || pattern.equalsIgnoreCase(
                "None") || pattern.equalsIgnoreCase("null");
        if (!isEmpty) {
            this.patternReplacer = new OptionalPatternReplacer(pattern, requiredComponents,
                                                               "Subject Alternative Name Provider"
            );
        } else {
            this.patternReplacer = null;
        }
    }

    @Override
    public Result<String, TextError> getSan(Supplier<Map<String, String>> keyValueSource) {
        if (isEmpty) return Result.success(null);
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

            return Result.success(patternReplacer.replacePattern(sanitizedSource));
        } catch (Exception e) {
            return Result.error(TextError.of("Could not create SAN based on the provided pattern. %s", e.getMessage()));
        }
    }
}
