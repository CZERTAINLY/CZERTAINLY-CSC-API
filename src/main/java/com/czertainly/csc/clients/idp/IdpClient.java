package com.czertainly.csc.clients.idp;

import com.czertainly.csc.common.exceptions.RemoteSystemException;
import com.czertainly.csc.configuration.idp.IdpConfiguration;
import com.czertainly.csc.model.UserInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.HashMap;
import java.util.Map;

@Component
public class IdpClient {


    private static final Logger logger = LoggerFactory.getLogger(IdpClient.class);
    private final RestClient restClient;
    private final boolean canDownloadUserInfo;
    private final String jwksUri;
    private final String userInfoUri;

    public IdpClient(IdpConfiguration idpConfiguration,
                     @Qualifier("idpClientRequestFactory") HttpComponentsClientHttpRequestFactory requestFactory
    ) {
        String userInfoUrl = idpConfiguration.userInfoUrl();
        canDownloadUserInfo = idpConfiguration.userInfoUrl() != null && !userInfoUrl.equals("none");
        this.userInfoUri = userInfoUrl;
        this.jwksUri = idpConfiguration.jwksUri();

        this.restClient = RestClient.builder()
                                    .requestFactory(requestFactory)
                                    .build();

        if (!canDownloadUserInfo) {
            logger.info("Application is not configured to download user info.");
        }
    }


    public UserInfo downloadUserInfo(String token) {
        if (!canDownloadUserInfo) {
            throw new UnsupportedOperationException("Application is not configured to download user info.");
        }
        logger.debug("Downloading user info from IDP.");
        logger.trace("Using token '{}' to download the user info.", token);
        ResponseEntity<String> response = restClient.get()
                                                    .uri(this.userInfoUri)
                                                    .header("Authorization", "Bearer " + token)
                                                    .accept(MediaType.APPLICATION_JSON)
                                                    .retrieve()
                                                    .toEntity(String.class);

        try {
            JsonNode json = new ObjectMapper().readTree(response.getBody());
            Map<String, String> attributes = new HashMap<>();
            var fields = json.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                attributes.put(field.getKey(), field.getValue().asText());
            }
            return new UserInfo(attributes);
        } catch (JsonProcessingException e) {
            throw new RemoteSystemException("Failed to parse response from IDP into a JSON object.", e);
        }
    }

    public String downloadJwks() {
        logger.debug("Downloading JWKS from the IDP.");

        return restClient.get()
                         .uri(this.jwksUri)
                         .accept(MediaType.APPLICATION_JSON)
                         .retrieve()
                         .body(String.class);
    }


    public boolean canDownloadUserInfo() {
        return canDownloadUserInfo;
    }
}
