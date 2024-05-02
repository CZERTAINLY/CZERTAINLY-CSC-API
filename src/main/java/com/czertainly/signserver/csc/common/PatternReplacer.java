package com.czertainly.signserver.csc.common;

import com.czertainly.signserver.csc.common.exceptions.InputDataException;
import org.apache.commons.text.StringSubstitutor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PatternReplacer {

    private final String pattern;
    private final String replacerName;

    public PatternReplacer(String pattern, String replacerName) {
        this.pattern = pattern;
        this.replacerName = replacerName;
    }

    private static final Pattern variableRegex = Pattern.compile("\\$\\[([^]]+)]");

    public String replacePattern(Supplier<Map<String, String>> keyValueSource) {
        StringSubstitutor sub = new StringSubstitutor(keyValueSource.get());
        sub.setVariablePrefix("$[");
        sub.setVariableSuffix("]");
        String processedPattern = sub.replace(pattern);
        Matcher matcher = variableRegex.matcher(processedPattern);

        if (!matcher.find()) {
            return processedPattern;
        } else {
            List<String> notReplacedVariables = new ArrayList<>();
            notReplacedVariables.add(matcher.group(1));
            while (matcher.find()) {
                notReplacedVariables.add(matcher.group(1));
            }
            throw new InputDataException(
                    "Not all variables could be replaced in the pattern provided to " + replacerName +
                            ". Unknown variables: [" + String.join(", ", notReplacedVariables) + "]");
        }
    }
}
