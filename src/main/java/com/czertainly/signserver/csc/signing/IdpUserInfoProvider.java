package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.clients.idp.IdpClient;
import com.czertainly.signserver.csc.model.UserInfo;
import org.springframework.stereotype.Component;

@Component
public class IdpUserInfoProvider implements UserInfoProvider {

    IdpClient idpClient;

    public IdpUserInfoProvider(IdpClient idpClient) {
        this.idpClient = idpClient;
    }

    @Override
    public UserInfo getUserInfo(String token) {
        try {
            return idpClient.downloadUserInfo(token);
        } catch (Exception e) {
            return null;
        }
    }

}
