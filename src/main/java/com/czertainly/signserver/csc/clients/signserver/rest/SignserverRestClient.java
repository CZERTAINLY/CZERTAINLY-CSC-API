package com.czertainly.signserver.csc.clients.signserver.rest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Base64;
import java.util.Map;

@Component
public class SignserverRestClient {

    public static final String WORKERS_REST_API_PATH = "/rest/v1/";
    public static final String WORKER_PROCESS_REST_API_PATH = WORKERS_REST_API_PATH + "workers/{workerName}/process";

    RestClient restClient;
    private final String basicAuth = "Basic " + Base64.getEncoder().encodeToString("user:password".getBytes());


    public SignserverRestClient(@Value("${signserver.url}") String signserverUrl,
                                HttpComponentsClientHttpRequestFactory requestFactory
    ) {
        restClient = RestClient.builder()
                               .requestFactory(requestFactory)
                               .baseUrl(signserverUrl)
                               .build();
    }

    public WorkerProcessResponse process(String workerName, byte[] data, Map<String, String> metadata,
                                         SignserverProcessEncoding encoding
    ) {
        final String requestData;
        if (encoding == SignserverProcessEncoding.BASE64) {
            requestData = Base64.getEncoder().encodeToString(data);
        } else {
            requestData = new String(data);
        }
        WorkerProcessRequest workerProcessRequest = new WorkerProcessRequest(requestData, metadata, encoding);

        return restClient
                .post()
                .uri(WORKER_PROCESS_REST_API_PATH, workerName)
                .body(workerProcessRequest)
                .header("Authorization", basicAuth)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .body(WorkerProcessResponse.class);
    }
}