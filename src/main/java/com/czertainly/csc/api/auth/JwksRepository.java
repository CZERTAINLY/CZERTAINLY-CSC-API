package com.czertainly.csc.api.auth;

import com.czertainly.csc.api.auth.exceptions.JwkLookupException;
import com.czertainly.csc.api.auth.exceptions.JwksDownloadException;
import com.czertainly.csc.clients.idp.IdpClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import io.jsonwebtoken.security.PublicJwk;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.util.Map;

@Component
public class JwksRepository {

    private static final Logger logger = LogManager.getLogger(JwksRepository.class);

    private final IdpClient idpClient;
    private final JwksParser jwksParser;

    private final Map<String, PublicKey> signingKeys;
    private final Map<String, PublicKey> encryptionKeys;

    public JwksRepository(IdpClient idpClient, JwksParser jwksParser) {
        assert idpClient != null;
        assert jwksParser != null;
        this.idpClient = idpClient;
        this.jwksParser = jwksParser;
        this.signingKeys = new java.util.HashMap<>();
        this.encryptionKeys = new java.util.HashMap<>();
    }

    public PublicKey getKey(String kid, String usage) throws JwkLookupException {
        logger.debug("Looking up for a key with usage '{}' and key id '{}'.", usage, kid);
        if (usage.equals("sig")) {
            return getKey(kid, signingKeys);
        } else if (usage.equals("enc")) {
            return getKey(kid, encryptionKeys);
        } else {
            throw new JwkLookupException("Unknown key usage: " + usage);
        }
    }

    private PublicKey getKey(String kid, Map<String, PublicKey> keyMap) throws JwkLookupException {
        if (keyMap.containsKey(kid)) {
            return keyMap.get(kid);
        } else {
            refreshKeys();
            return keyMap.getOrDefault(kid, null);
        }
    }

    private Result<Void, TextError> refreshKeys() throws JwksDownloadException {
        logger.debug("Refreshing JWKs.");
        return idpClient.downloadJwks()
                        .flatMap(jwksParser::parse)
                        .ifSuccess(signingKeys::clear)
                        .ifSuccess(encryptionKeys::clear)
                        .consume(keys -> {
                            for (PublicJwk<?> jwk : keys) {
                                if (jwk.getPublicKeyUse().equals("sig")) {
                                    logger.trace("Registering signing key with kid: {}", jwk.getId());
                                    this.signingKeys.put(jwk.getId(), jwk.toKey());
                                } else if (jwk.getPublicKeyUse().equals("enc")) {
                                    logger.trace("Registering signing key with kid: {}", jwk.getId());
                                    this.encryptionKeys.put(jwk.getId(), jwk.toKey());
                                }
                            }
                        })
                        .flatMap((v) -> Result.emptySuccess())
                        .consumeError(e -> logger.warn("Failed to refresh keys. " + e.getErrorText()));
    }
}
