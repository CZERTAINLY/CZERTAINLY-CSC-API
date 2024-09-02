package com.czertainly.csc.providers;

import com.czertainly.csc.common.OptionalPatternReplacer;
import com.czertainly.csc.common.PatternReplacer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

@Component
public class PatternSanProvider implements SubjectAlternativeNameProvider {

    private final OptionalPatternReplacer patternReplacer;
    private final boolean isEmpty;

    public PatternSanProvider(@Value("${caProvider.ejbca.endEntity.san.pattern}") String pattern, @Value("${caProvider.ejbca.endEntity.san.required}") List<String> requiredComponents) {
        this.isEmpty = pattern.isBlank() || pattern.equalsIgnoreCase("None") || pattern.equalsIgnoreCase("null");
        if (!isEmpty) {
            this.patternReplacer = new OptionalPatternReplacer(pattern, requiredComponents, "Subject Alternative Name Provider");
        } else {
            this.patternReplacer = null;
        }
    }

    @Override
    public String getSan(Supplier<Map<String, String>> keyValueSource) {
        if (isEmpty) return null;
        return patternReplacer.replacePattern(keyValueSource);
    }
}
