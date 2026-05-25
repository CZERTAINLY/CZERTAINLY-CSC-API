package com.otilm.csc.signing;

import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import com.otilm.csc.model.UserInfo;

public interface UserInfoProvider {

    Result<UserInfo, TextError> getUserInfo(String identifier);

}
