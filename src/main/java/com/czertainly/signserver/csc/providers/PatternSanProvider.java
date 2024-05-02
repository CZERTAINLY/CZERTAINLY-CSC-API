package com.czertainly.signserver.csc.providers;

import com.czertainly.signserver.csc.common.PatternReplacer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.function.Supplier;

@Component
public class PatternSanProvider implements SubjectAlternativeNameProvider {

    private final PatternReplacer patternReplacer;
    private final boolean isEmpty;

    public PatternSanProvider(@Value("${caProvider.ejbca.sanPattern}") String pattern) {
        this.patternReplacer = new PatternReplacer(pattern, "Subject Alternative Name Provider");
        this.isEmpty = pattern.isBlank() || pattern.equalsIgnoreCase("None") || pattern.equalsIgnoreCase("null");
    }

    @Override
    public String getSan(Supplier<Map<String, String>> keyValueSource) {
        if (isEmpty) return null;
        return patternReplacer.replacePattern(keyValueSource);
    }
}
