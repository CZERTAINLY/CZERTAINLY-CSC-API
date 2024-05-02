package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.common.exceptions.InputDataException;
import com.czertainly.signserver.csc.model.UserInfo;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component
public class PatternDNProvider implements DistinguishedNameProvider {

    String pattern;

    public PatternDNProvider(@Value("${caProvider.ejbca.dnPattern}") String pattern) {
        this.pattern = pattern;
    }
    private static final Pattern variableRegex = Pattern.compile("\\$\\[([^]]+)]");

    @Override
    public String getDistinguishedName(UserInfo userInfo) {
        StringSubstitutor sub = new StringSubstitutor(userInfo.getAttributes());
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
            throw new InputDataException("Not all variables could be replaced in the pattern provided. Unknown variables: [" + String.join(
                    ", ", notReplacedVariables) + "]");
        }
    }
}
