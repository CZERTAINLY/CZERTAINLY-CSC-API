package com.czertainly.signserver.csc.providers;

import com.czertainly.signserver.csc.common.PatternReplacer;
import com.czertainly.signserver.csc.common.exceptions.ApplicationConfigurationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.function.Supplier;

@Component
public class PatternDnProvider implements DistinguishedNameProvider {

    private final PatternReplacer patternReplacer;

    public PatternDnProvider(@Value("${caProvider.ejbca.dnPattern}") String dnPattern) {
        if (dnPattern.isBlank()) {
            throw new ApplicationConfigurationException("Distinguished Name pattern is not set.");
        }
        this.patternReplacer = new PatternReplacer(dnPattern, "Distinguished Name Provider");;
    }
    @Override
    public String getDistinguishedName(Supplier<Map<String, String>> keyValueSource) {
        return patternReplacer.replacePattern(keyValueSource);
    }
}
