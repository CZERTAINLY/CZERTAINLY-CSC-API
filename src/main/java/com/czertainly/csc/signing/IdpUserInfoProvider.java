package com.czertainly.csc.signing;

import com.czertainly.csc.clients.idp.IdpClient;
import com.czertainly.csc.model.UserInfo;
import org.springframework.stereotype.Component;

@Component
public class IdpUserInfoProvider implements UserInfoProvider {

    private final IdpClient idpClient;


    public IdpUserInfoProvider(IdpClient idpClient) {
        this.idpClient = idpClient;
    }

    @Override
    public UserInfo getUserInfo(String token) {
            if (idpClient.canDownloadUserInfo()) {
                return idpClient.downloadUserInfo(token);
            }
            return null;
    }
}
