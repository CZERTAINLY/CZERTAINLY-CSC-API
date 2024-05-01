package com.czertainly.signserver.csc.clients.idp;

import com.czertainly.signserver.csc.common.exceptions.RemoteSystemException;
import com.czertainly.signserver.csc.model.UserInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    RestClient restClient;


    public IdpClient(@Value("${idp.userInfoUrl}") String signserverUrl) {
        restClient = RestClient.builder()
                               .requestFactory(new HttpComponentsClientHttpRequestFactory())
                               .baseUrl(signserverUrl)
                               .build();
    }

    public UserInfo downloadUserInfo(String token) {
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
}
