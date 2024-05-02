package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.model.UserInfo;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class PatternDNProvider implements DistinguishedNameProvider {

    String pattern;

    public PatternDNProvider(@Value("${dnPattern}") String pattern) {
        this.pattern = pattern;
    }

    @Override
    public String getDistinguishedName(UserInfo userInfo) {
        StringSubstitutor sub = new StringSubstitutor(userInfo.getAttributes());
        sub.setVariablePrefix("@{");
        return sub.replace(pattern);
    }
}
