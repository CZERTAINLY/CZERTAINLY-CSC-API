package com.czertainly.signserver.csc.clients.signserver.rest;

import com.czertainly.signserver.csc.common.exceptions.RemoteSystemException;
import com.czertainly.signserver.csc.configuration.SignApiAuthorization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class SignserverRestClient {

    public static final Logger log = LoggerFactory.getLogger(SignserverRestClient.class);

    public static final String WORKERS_REST_API_PATH = "/rest/v1/";
    public static final String WORKER_PROCESS_REST_API_PATH = WORKERS_REST_API_PATH + "workers/{workerName}/process";

    RestClient restClient;
    private final String basicAuthHeader;


    public SignserverRestClient(
            @Value("${signingProvider.signserver.url}") String signserverUrl,
            @Value("${signingProvider.signserver.authorization.type}") SignApiAuthorization authzType,
            @Value("${signingProvider.signserver.authorization.basic.username}") String basicAuthUsername,
            @Value("${signingProvider.signserver.authorization.basic.password}") String basicAuthPassword,
            HttpComponentsClientHttpRequestFactory requestFactory
    ) {
        log.debug("Creating SignserverRestClient with base URL: {}", signserverUrl);
        restClient = RestClient.builder().requestFactory(requestFactory).baseUrl(signserverUrl).build();
        if (authzType == SignApiAuthorization.BASIC) {
            basicAuthHeader = "Basic " + Base64.getEncoder().encodeToString((basicAuthUsername + ":" + basicAuthPassword).getBytes());
        } else {
            basicAuthHeader = null;
        }
    }

    public WorkerProcessResponse process(String workerName, byte[] data, Map<String, String> metadata,
                                         SignserverProcessEncoding encoding
    ) {
        log.debug("Calling Signserver process API. WorkerName: {}, Encoding: {}, metadata: [{}]",
                  workerName, encoding,
                  metadata.entrySet().stream()
                          .map(e -> e.getKey() + "=" + e.getValue())
                          .collect(Collectors.joining(", "))
        );
        final String requestData;
        if (encoding == SignserverProcessEncoding.BASE64) {
            requestData = Base64.getEncoder().encodeToString(data);
        } else {
            requestData = new String(data);
        }
        WorkerProcessRequest workerProcessRequest = new WorkerProcessRequest(requestData, metadata, encoding);
        try {
            return restClient.post().uri(WORKER_PROCESS_REST_API_PATH, workerName).body(workerProcessRequest)
                             .contentType(MediaType.APPLICATION_JSON)
                             .header("Authorization", basicAuthHeader)
                             .accept(MediaType.APPLICATION_JSON).retrieve().body(WorkerProcessResponse.class);
        } catch (Exception e) {
            throw new RemoteSystemException("Processing failed on worker " + workerName, e);
        }
    }
}