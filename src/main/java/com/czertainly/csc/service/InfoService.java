package com.czertainly.csc.service;

import com.czertainly.csc.api.info.InfoDto;
import com.czertainly.csc.api.info.SignatureAlgorithmsDto;
import com.czertainly.csc.api.info.SignatureFormatsDto;
import com.czertainly.csc.configuration.csc.CscConfiguration;
import com.czertainly.csc.configuration.idp.IdpConfiguration;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;


@Component
public class InfoService {

    String componentName;
    String logoUri;
    String region;
    String idbBaseUri;
    WorkerRepository workerRepository;

    SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();

    public InfoService(
            CscConfiguration cscConfiguration,
            IdpConfiguration idpConfiguration,
            WorkerRepository workerRepository
    ) {
        this.componentName = cscConfiguration.name();
        this.logoUri = cscConfiguration.logo();
        this.region = cscConfiguration.region();
        this.idbBaseUri = idpConfiguration.baseUrl();
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
                List.of("info", "credential/list", "credential/info", "signatures/signDoc", "signatures/signHash"),
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
                               .map(worker -> worker.capabilities().conformanceLevel())
                               .filter(Objects::nonNull)
                               .map(Enum::toString)
                               .distinct().toList();
    }

    private List<String> getSupportedSignatureFormats() {
        return workerRepository.getAllWorkers().stream()
                               .map(worker -> worker.capabilities().signatureFormat())
                               .filter(Objects::nonNull)
                               .map(Enum::toString)
                               .distinct().toList();
    }

    private List<List<String>> getSupportedEnvelopeProperties(List<String> signatureFormats) {

        List<List<String>> envelopePropertiesBySignatureFormat = new ArrayList<>();

        for (String signatureFormat : signatureFormats) {
            envelopePropertiesBySignatureFormat.add(
                    workerRepository.getAllWorkers().stream()
                                    .filter(worker -> {
                                        SignatureFormat sigFmt = worker.capabilities().signatureFormat();
                                        if (sigFmt == null) {
                                            return false;
                                        }
                                        return sigFmt.toString().equals(signatureFormat);
                                    })
                                    .map(worker -> worker.capabilities().signaturePackaging())
                                    .filter(Objects::nonNull)
                                    .map(Enum::toString)
                                    .distinct().toList()
            );
        }
        return envelopePropertiesBySignatureFormat;
    }

    private List<String> getSupportedSignatureAlgorithms() {
        return workerRepository.getAllWorkers().stream()
                               .flatMap(worker -> worker.capabilities().supportedSignatureAlgorithms().stream())
                               .distinct()
                               .map(alg -> signatureAlgorithmIdentifierFinder.find(alg).getAlgorithm().toString())
                               .toList();
    }

}
