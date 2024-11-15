package com.czertainly.csc.signing;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.UserInfo;

public interface UserInfoProvider {

    Result<UserInfo, TextError> getUserInfo(String identifier);

}
