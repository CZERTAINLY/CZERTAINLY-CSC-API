package com.czertainly.csc.service;

import com.czertainly.csc.api.info.InfoDto;
import com.czertainly.csc.api.info.SignatureFormatsDto;
import com.czertainly.csc.api.info.SignatureAlgorithmsDto;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;


@Component
public class InfoService {

    String componentName;
    String logoUri;
    String region;

    String idbBaseUri;
    WorkerRepository workerRepository;

    SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();

    public InfoService(
            @Value("${csc.name}") String componentName,
            @Value("${csc.logo}") String logoUri,
            @Value("${csc.region}") String region,
            @Value("${idp.baseUrl}") String idbBaseUri,
            WorkerRepository workerRepository) {
        this.componentName = componentName;
        this.logoUri = logoUri;
        this.region = region;
        this.idbBaseUri = idbBaseUri;
        this.workerRepository = workerRepository;
    }
    public InfoDto getInfo() {
        return new InfoDto(
                "2.0.0.0",
                componentName,
                logoUri,
                region,
                "en",
                List.of("oauth2client"),
                idbBaseUri,
                null,
                false,
                List.of("info", "signatures/signDoc"),
                true,
                new SignatureAlgorithmsDto(
                        getSupportedSignatureAlgorithms(),
                        null
                ),
                new SignatureFormatsDto(
                        getSupportedSignatureFormats(),
                        getSupportedEnvelopeProperties(getSupportedSignatureFormats())
                ),
                getSupportedEnvelopeProperties()
        );
    }

    private List<String> getSupportedEnvelopeProperties() {
        return workerRepository.getAllWorkers().stream()
                               .map(worker -> worker.capabilities().conformanceLevel().toString())
                               .distinct().toList();
    }

    private List<String> getSupportedSignatureFormats() {
        return workerRepository.getAllWorkers().stream()
                               .map(worker -> worker.capabilities().signatureFormat().toString())
                               .distinct().toList();
    }

    private List<List<String>> getSupportedEnvelopeProperties(List<String> signatureFormats) {

        List<List<String>> envelopePropertiesBySignatureFormat = new ArrayList<>();

        for (String signatureFormat : signatureFormats) {
            envelopePropertiesBySignatureFormat.add(
                    workerRepository.getAllWorkers().stream()
                                    .filter(worker -> worker.capabilities().signatureFormat().toString()
                                                            .equals(signatureFormat))
                                    .map(worker -> worker.capabilities().signaturePackaging().toString())
                                    .distinct().toList()
            );
        }
        return envelopePropertiesBySignatureFormat;
    }

    private List<String> getSupportedSignatureAlgorithms() {
        return workerRepository.getAllWorkers().stream()
                               .flatMap(worker -> worker.capabilities().supportedSignatureAlgorithms().stream().map(alg -> signatureAlgorithmIdentifierFinder.find(alg).getAlgorithm().toString()))
                               .distinct()
                               .toList();
    }

}
