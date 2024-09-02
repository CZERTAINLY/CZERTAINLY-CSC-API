package com.czertainly.csc.providers;

import com.czertainly.csc.common.OptionalPatternReplacer;
import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.common.PatternReplacer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

@Component
public class PatternDnProvider implements DistinguishedNameProvider {

    private final OptionalPatternReplacer patternReplacer;

    public PatternDnProvider(@Value("${caProvider.ejbca.endEntity.dn.pattern}") String dnPattern, @Value("${caProvider.ejbca.endEntity.dn.required}") List<String> requiredComponents) {
        if (dnPattern.isBlank()) {
            throw new ApplicationConfigurationException("Distinguished Name pattern is not set.");
        }
        if (requiredComponents.isEmpty()) {
            throw new ApplicationConfigurationException("Distinguished Name required components are not set.");
        }
        this.patternReplacer = new OptionalPatternReplacer(dnPattern, requiredComponents, "Distinguished Name Provider");
    }
    @Override
    public String getDistinguishedName(Supplier<Map<String, String>> keyValueSource) {
        return patternReplacer.replacePattern(keyValueSource);
    }
}
