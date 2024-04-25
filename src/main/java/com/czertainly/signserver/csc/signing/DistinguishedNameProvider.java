package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.model.UserInfo;

public interface DistinguishedNameProvider {

    String getDistinguishedName(UserInfo userInfo);
}
