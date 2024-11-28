package com.czertainly.csc.configuration.keypools;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.validation.annotation.Validated;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Validated
@ConfigurationProperties
public record KeyPoolProfilesConfiguration(List<KeyPoolProfile> keyPoolProfiles) implements Validator {

    @Override
    public boolean supports(Class<?> clazz) {
        return KeyPoolProfilesConfiguration.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        KeyPoolProfilesConfiguration config = (KeyPoolProfilesConfiguration) target;
        if (config.keyPoolProfiles() == null || config.keyPoolProfiles().isEmpty()) {
            errors.rejectValue("keyPoolProfiles", "keyPoolProfiles.empty", "Key pool profiles must be defined");
            return;
        }

        Map<String, KeyPoolProfile> keyPoolProfileConfiguration = new HashMap<>();
        for (KeyPoolProfile p : config.keyPoolProfiles()) {
            String configString = String.format("%s:%s:%s", p.designatedUsage(), p.keyAlgorithm(),
                                                p.keySpecification()
            );
            if (keyPoolProfileConfiguration.containsKey(configString)) {
                KeyPoolProfile duplicate = keyPoolProfileConfiguration.get(configString);
                errors.rejectValue("keyPoolProfiles", "keyPoolProfiles.interfere",
                                   String.format(
                                           "Configuration of key pool profiles '%s' and '%s' interfere. A triplet of Key Algorithm, Key Specification and Designated Usage must be unique.",
                                           p.name(), duplicate.name()
                                   )
                );
            } else {
                keyPoolProfileConfiguration.put(configString, p);
            }
        }
    }
}
