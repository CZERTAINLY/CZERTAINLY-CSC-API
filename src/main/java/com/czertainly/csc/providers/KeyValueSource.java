package com.czertainly.csc.providers;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class KeyValueSource {

    private static final Logger logger = LoggerFactory.getLogger(KeyValueSource.class);

    private final String KeyAlias;
    private final UserInfo userInfo;
    private final CscAuthenticationToken cscAuthenticationToken;
    private final SignatureActivationData sad;

    public KeyValueSource(String keyAlias, UserInfo userInfo, CscAuthenticationToken cscAuthenticationToken, SignatureActivationData sad) {
        KeyAlias = keyAlias;
        this.userInfo = userInfo;
        this.cscAuthenticationToken = cscAuthenticationToken;
        this.sad = sad;
    }

    public Map<String, String> get() {
        Map<String, String> properties = new HashMap<>();
        addProperty(properties, "Credential.id", KeyAlias);
        addProperty(properties, "Sad.clientData", sad.getClientData().orElse(""));
        if (userInfo != null) {
            userInfo.getAttributes().forEach((key, value) -> addProperty(properties,"UserInfo." + key, value));
        }
        cscAuthenticationToken.getTokenAttributes().forEach(
                (key, value) -> addProperty(properties,"AccessToken." + key, value.toString()));
        return properties;
    }

    private void addProperty(Map<String, String> properties, String key, String value) {
        logger.trace("Adding property {} with value {} into KeyValue Source", key, value);
        properties.put(key, value);
    }
}
