package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.model.UserInfo;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class PatternDNProvider implements DistinguishedNameProvider {

    String pattern;

    public PatternDNProvider(@Value("${caProvider.ejbca.dnPattern}") String pattern) {
        this.pattern = pattern;
    }


    // TODO: return 400
    @Override
    public String getDistinguishedName(UserInfo userInfo) {
        StringSubstitutor sub = new StringSubstitutor(userInfo.getAttributes());
        sub.setVariablePrefix("@(");
        sub.setVariableSuffix(")");
        return sub.replace(pattern);
    }
}
