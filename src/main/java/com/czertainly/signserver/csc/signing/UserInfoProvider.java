package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.model.UserInfo;

public interface UserInfoProvider {

    UserInfo getUserInfo(String identifier);

}
