package com.czertainly.csc.common;

import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OptionalPatternReplacer {

    private static final Logger logger = LoggerFactory.getLogger(OptionalPatternReplacer.class);
    private final List<PatternComponent> allComponents;
    private final List<String> requiredComponents;
    private final String replacerName;

    public OptionalPatternReplacer(String pattern, List<String> requiredComponents, String replacerName) {
        this.replacerName = replacerName;
        this.requiredComponents = requiredComponents;
        this.allComponents = parsePatternToComponents(pattern);
    }

    private static final Pattern toComponentPattern = Pattern.compile("([a-zA-Z1-9]+)=\\$\\[([^]]+)]");

    private List<PatternComponent> parsePatternToComponents(String pattern) {
        Matcher matcher = toComponentPattern.matcher(pattern);
        List<PatternComponent> components = new ArrayList<>();
        while (matcher.find()) {
            String name = matcher.group(1);
            String variable = matcher.group(2);
            var component = new PatternComponent(name, variable);
            logger.debug("Adding component '{}' with replaceable value '{}' into '{}'", component.name(), component.variable, replacerName);
            components.add(component);
        }
        return components;
    }

    public String replacePattern(Supplier<Map<String, String>> keyValueSource) {

        List<String> substitutedComponents = new ArrayList<>();

        for (PatternComponent component : allComponents) {
            var isValueAvailable = keyValueSource.get().containsKey(component.variable);
            var isComponentRequired = requiredComponents.contains(component.name());
            if (!isValueAvailable && isComponentRequired) {
                throw new InvalidInputDataException(
                        replacerName + ": Missing value of '" + component.variable + "' for required component '" + component.name +"'.");
            } else if (isValueAvailable) {
                substitutedComponents.add(component.name() + "=" + keyValueSource.get().get(component.variable));
            }

        }

        return String.join(", ", substitutedComponents);
    }

    private record PatternComponent(String name, String variable) { }
}
