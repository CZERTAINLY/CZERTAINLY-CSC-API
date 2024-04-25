package com.czertainly.signserver.csc.clients.signserver.rest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Component
public class SignserverRestClient {

    public static final String WORKERS_REST_API_PATH = "/rest/v1/";
    public static final String WORKER_PROCESS_REST_API_PATH = WORKERS_REST_API_PATH + "workers/{workerName}/process";

    RestClient restClient;


    public SignserverRestClient(@Value("${signserver.url}") String signserverUrl) {
        restClient = RestClient.builder()
                               .requestFactory(new JdkClientHttpRequestFactory())
                               .baseUrl(signserverUrl)
                               .build();
    }

    public void process(String workerName, String data, Map<String, String> metadata, SignserverProcessEncoding encoding) {
        WorkerProcessRequest workerProcessRequest = new WorkerProcessRequest(data, metadata, encoding);

        WorkerProcessResponse response = restClient.post()
                                                    .uri(WORKER_PROCESS_REST_API_PATH, workerName)
                                                    .body(workerProcessRequest)
                                                    .contentType(MediaType.APPLICATION_JSON)
                                                    .accept(MediaType.APPLICATION_JSON)
                                                    .retrieve()
                                                    .body(WorkerProcessResponse.class);

        System.out.println(response);
    }
}
