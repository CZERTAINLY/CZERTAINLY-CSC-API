package com.czertainly.signserver.csc.service;

import com.czertainly.signserver.csc.api.info.InfoDto;
import com.czertainly.signserver.csc.api.info.SignatureAlgorithmsDto;
import com.czertainly.signserver.csc.api.info.SignatureFormatsDto;
import com.czertainly.signserver.csc.signing.configuration.WorkerRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;


@Component
public class InfoService {

    String idbBaseUri;
    WorkerRepository workerRepository;

    public InfoService(@Value("${idp.baseUrl}") String idbBaseUri, WorkerRepository workerRepository) {
        this.idbBaseUri = idbBaseUri;
        this.workerRepository = workerRepository;
    }

    public InfoDto getInfo() {
        return new InfoDto(
                "2.0.0.0",
                "CZertainly Signing CSC",
                "https://www.czertainly.com/web/image/website/2/logo/CZERTAINLY?unique=847b5c1",
                "CZ",
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
                               .flatMap(worker -> worker.capabilities().supportedSignatureAlgorithms().stream())
                               .distinct()
                               .toList();
    }

}
