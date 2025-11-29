package com.czertainly.csc.clients.idp;

import com.czertainly.csc.common.errorhandling.ErrorResultRetryException;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.common.result.TextErrorWithRetryIndication;
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
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.util.HashMap;
import java.util.Map;

@Component
@Retryable(
        retryFor = {ErrorResultRetryException.class},
        maxAttempts = 3,
        backoff = @Backoff(delay = 1000, multiplier = 2),
        listeners = {"resultRetryListener"})
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
        canDownloadUserInfo = idpConfiguration.userInfoUrl() != null && !userInfoUrl.isBlank();
        this.userInfoUri = userInfoUrl;
        this.jwksUri = idpConfiguration.jwksUri();

        this.restClient = RestClient.builder()
                                    .requestFactory(requestFactory)
                                    .build();

        if (!canDownloadUserInfo) {
            logger.info("Application is not configured to download user info.");
        }
    }


    public Result<UserInfo, TextError> downloadUserInfo(String token) {
        try {
            if (!canDownloadUserInfo) {
                Result.error(TextErrorWithRetryIndication.doNotRetry(
                        "Application is not configured to download user info."));
            }
            logger.debug("Downloading user info from IDP.");
            logger.trace("Using token '{}' to download the user info.", token);

            ResponseEntity<String> response = restClient.get()
                                                        .uri(this.userInfoUri)
                                                        .header("Authorization", "Bearer " + token)
                                                        .accept(MediaType.APPLICATION_JSON)
                                                        .retrieve()
                                                        .toEntity(String.class);


            JsonNode json = new ObjectMapper().readTree(response.getBody());
            Map<String, String> attributes = new HashMap<>();
            var fields = json.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                attributes.put(field.getKey(), field.getValue().asText());
            }
            return Result.success(new UserInfo(attributes));
        } catch (ResourceAccessException e) {
            logger.error("Failed to download user info from IDP.", e);
            return Result.error(TextErrorWithRetryIndication.doRetry("Failed to obtain user info from the IDP."));
        } catch (JsonProcessingException e) {
            logger.error("Failed to parse response from IDP into a JSON object.", e);
            return Result.error(
                    TextErrorWithRetryIndication.doNotRetry("Failed to parse response from IDP into a JSON object."));
        }
    }

    public Result<String, TextError> downloadJwks() {
        logger.debug("Downloading JWKS from the IDP.");
        try {
            String jwks = restClient.get()
                                    .uri(this.jwksUri)
                                    .accept(MediaType.APPLICATION_JSON)
                                    .retrieve()
                                    .body(String.class);
            return Result.success(jwks);
        } catch (ResourceAccessException e) {
            logger.error("Failed to download JWKS from the IDP.", e);
            return Result.error(TextErrorWithRetryIndication.doRetry("Failed to obtain JWKS from the IDP."));
        } catch (Exception e) {
            logger.error("Failed to download JWKS from the IDP.", e);
            return Result.error(TextErrorWithRetryIndication.doNotRetry("Failed to obtain JWKS from the IDP."));
        }
    }

    public boolean canDownloadUserInfo() {
        return canDownloadUserInfo;
    }
}
