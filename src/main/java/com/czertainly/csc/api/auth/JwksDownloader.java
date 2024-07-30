package com.czertainly.csc.api.auth;

import com.czertainly.csc.api.auth.exceptions.JwksDownloadException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class JwksDownloader {

    private final Logger logger = LogManager.getLogger(JwksDownloader.class);

    private final RestClient restClient;

    public JwksDownloader(@Value("${idp.jwksUri}") String jwksUri,
                          HttpComponentsClientHttpRequestFactory requestFactory
    ) {
        try {
            restClient = RestClient.builder()
                                   .requestFactory(requestFactory)
                                   .baseUrl(jwksUri)
                                   .build();
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to configure JWKSDownloader", e);
        }
    }

    public String download() throws JwksDownloadException {
        logger.debug("Downloading JWKS from the IDP.");

        return restClient.get()
                         .accept(MediaType.APPLICATION_JSON)
                         .retrieve()
                         .body(String.class);
    }
}

