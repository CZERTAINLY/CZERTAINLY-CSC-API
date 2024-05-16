package com.czertainly.csc.clients.idp;

import com.czertainly.csc.common.exceptions.RemoteSystemException;
import com.czertainly.csc.model.UserInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
    RestClient restClient;
    boolean canDownloadUserInfo;


    public IdpClient(@Value("${idp.userInfoUrl:none}") String userInfoUrl) {
        canDownloadUserInfo = userInfoUrl != null && !userInfoUrl.equals("none");
        if (!canDownloadUserInfo) {
            return;
        }
        restClient = RestClient.builder()
                               .requestFactory(new HttpComponentsClientHttpRequestFactory())
                               .baseUrl(userInfoUrl)
                               .build();
    }

    public UserInfo downloadUserInfo(String token) {
        if (!canDownloadUserInfo) {
            throw new UnsupportedOperationException("Application is not configured to download user info.");
        }
        logger.debug("Downloading user info from IDP.");
        logger.trace("Using token '{}' to download the user info.", token);
        ResponseEntity<String> response = restClient.get()
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

    public boolean canDownloadUserInfo() {
        return canDownloadUserInfo;
    }
}
