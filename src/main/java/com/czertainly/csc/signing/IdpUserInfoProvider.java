package com.czertainly.csc.signing;

import com.czertainly.csc.clients.idp.IdpClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class IdpUserInfoProvider implements UserInfoProvider {

    private static final Logger logger = LoggerFactory.getLogger(IdpUserInfoProvider.class);
    private final IdpClient idpClient;


    public IdpUserInfoProvider(IdpClient idpClient) {
        this.idpClient = idpClient;
    }

    @Override
    public Result<UserInfo, TextError> getUserInfo(String token) {
        if (idpClient.canDownloadUserInfo()) {
                return idpClient.downloadUserInfo(token);
        } else {
            logger.debug("Application is not configured to download user info. Empty user info will be returned.");
            return Result.success(UserInfo.empty());
        }
    }
}
