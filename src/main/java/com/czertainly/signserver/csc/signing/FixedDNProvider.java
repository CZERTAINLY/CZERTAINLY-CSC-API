package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.model.UserInfo;
import org.springframework.stereotype.Component;

@Component
public class FixedDNProvider implements DistinguishedNameProvider {

    @Override
    public String getDistinguishedName(UserInfo userInfo) {
        return "CN=Test User, O=Test Org, C=CZ";
    }
}
