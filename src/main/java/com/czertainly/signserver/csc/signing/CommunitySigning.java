package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.clients.signserver.SignserverClient;
import com.czertainly.signserver.csc.signing.configuration.CapabilitiesFilter;
import com.czertainly.signserver.csc.signing.configuration.ConformanceLevel;
import com.czertainly.signserver.csc.signing.configuration.SignatureFormat;
import com.czertainly.signserver.csc.signing.configuration.WorkerRepository;
import org.springframework.stereotype.Component;

@Component
public class CommunitySigning {

    SignserverClient signserverClient;
    WorkerRepository workerRepository;
    KeySelector keySelector;
    DistinguishedNameProvider distinguishedNameProvider;


    public CommunitySigning(SignserverClient signserverClient, WorkerRepository workerRepository, NaiveKeySelector keySelector, DistinguishedNameProvider distinguishedNameProvider) {
        this.signserverClient = signserverClient;
        this.workerRepository = workerRepository;
        this.keySelector = keySelector;
        this.distinguishedNameProvider = distinguishedNameProvider;

    }

    public void signDocument() {
        var desiredCapabilities = CapabilitiesFilter.configure()
                .withSignatureQualifier("eu_eidas_qes")
                .withSignatureFormat(SignatureFormat.XAdES)
                .withConformanceLevel(ConformanceLevel.AdES_B_B)
                .build();

        var worker = workerRepository.selectWorker(desiredCapabilities);
        if (worker == null) {
            System.out.println("No worker found with desired capabilities");
            return;
        }

        var key = keySelector.selectKey(worker.worker().workerId());
        var dn = distinguishedNameProvider.getDistinguishedName(null);

        signserverClient
                .generateCSR(key.cryptoTokenId(), key.keyAlias(), dn, "SHA512WithRSA")
                .doWith(
                        csr -> System.out.println("CSR generated: " + csr.getSubject().toString()),
                        error -> System.out.println("Error while generating CSR: " + error.description())
                );
    }

}
