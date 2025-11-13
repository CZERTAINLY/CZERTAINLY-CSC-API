package com.czertainly.csc.providers;

import com.czertainly.csc.common.OptionalPatternReplacer;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public class PatternSanProvider implements SubjectAlternativeNameProvider {

    private final OptionalPatternReplacer patternReplacer;
    private final boolean isEmpty;

    public PatternSanProvider(String pattern, List<String> requiredComponents) {
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
            return Result.success(patternReplacer.replacePattern(keyValueSource));
        } catch (Exception e) {
            return Result.error(TextError.of("Could not create SAN based on the provided pattern. %", e.getMessage()));
        }
    }
}
