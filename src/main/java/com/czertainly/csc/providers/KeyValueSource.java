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

    public KeyValueSource(String keyAlias, UserInfo userInfo, CscAuthenticationToken cscAuthenticationToken,
                          SignatureActivationData sad
    ) {
        KeyAlias = keyAlias;
        this.userInfo = userInfo;
        this.cscAuthenticationToken = cscAuthenticationToken;
        this.sad = sad;
    }

    public Map<String, String> get() {
        Map<String, String> properties = new HashMap<>();

        addProperty(properties, "Credential.id", KeyAlias);
        addSadProperties(properties);
        addUserInfoProperties(properties);
        addAccessTokenProperties(properties);
        return properties;
    }

    private void addSadProperties(Map<String, String> properties) {
        sad.getClientData().ifPresent(value -> addProperty(properties, "Sad.clientData", value));
        sad.getCredentialID().ifPresent(value -> addProperty(properties, "Sad.credentialID", value));
        sad.getHashAlgorithmOID().ifPresent(value -> addProperty(properties, "Sad.hashAlgorithmOID", value));
        sad.getSignatureQualifier().ifPresent(value -> addProperty(properties, "Sad.signatureQualifier", value));
        sad.getHashes().ifPresent(value -> addProperty(properties, "Sad.hashes", String.join(",", value)));
        addProperty(properties, "Sad.numSignatures", String.valueOf(sad.getNumSignatures()));
        sad.getOtherAttributes().forEach((key, value) -> addProperty(properties, "Sad." + key, value));
    }

    private void addUserInfoProperties(Map<String, String> properties) {
        if (userInfo != null) {
            userInfo.getAttributes().forEach((key, value) -> addProperty(properties, "UserInfo." + key, value));
        }
    }

    private void addAccessTokenProperties(Map<String, String> properties) {
        cscAuthenticationToken.getTokenAttributes().forEach(
                (key, value) -> addProperty(properties, "AccessToken." + key, value.toString()));
    }

    private void addProperty(Map<String, String> properties, String key, String value) {
        logger.trace("Adding property {} with value {} into KeyValue Source", key, value);
        properties.put(key, value);
    }
}
