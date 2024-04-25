package com.czertainly.signserver.csc.api.auth;

import com.czertainly.signserver.csc.api.auth.exceptions.JwkLookupException;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.LocatorAdapter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.security.Key;

@Component
public class KeyLocator extends LocatorAdapter<Key> {

    private final Logger logger = LogManager.getLogger(KeyLocator.class.getName());
    JwksRepository repository;

    public KeyLocator(JwksRepository repository) {
        this.repository = repository;
    }

    @Override
    protected Key locate(JweHeader header) {
        try {
            return repository.getKey(header.getKeyId(), "enc");
        } catch (JwkLookupException e) {
            logger.warn("Failed to locate encryption key. {}", e.getMessage());
            return null;
        }
    }

    @Override
    protected Key locate(JwsHeader header) {
        try {
            return repository.getKey(header.getKeyId(), "sig");
        } catch (JwkLookupException e) {
            logger.warn("Failed to locate encryption key. {}", e.getMessage());
            return null;
        }
    }
}
