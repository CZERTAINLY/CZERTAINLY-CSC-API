package com.czertainly.signserver.csc.clients.signserver;

import com.czertainly.signserver.csc.clients.signserver.rest.SignserverProcessEncoding;
import com.czertainly.signserver.csc.clients.signserver.rest.SignserverRestClient;
import com.czertainly.signserver.csc.clients.signserver.ws.SignserverWSClient;
import com.czertainly.signserver.csc.clients.signserver.ws.dto.GetPKCS10CertificateRequestForAlias2Response;
import com.czertainly.signserver.csc.clients.signserver.ws.dto.TokenEntry;
import com.czertainly.signserver.csc.common.ErrorWithDescription;
import com.czertainly.signserver.csc.common.Result;
import com.czertainly.signserver.csc.model.builders.CryptoTokenKeyBuilder;
import com.czertainly.signserver.csc.model.signserver.CryptoTokenKey;
import com.czertainly.signserver.csc.model.signserver.CryptoTokenKeyStatus;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
public class SignserverClient {

    SignserverWSClient signserverWSClient;
    SignserverRestClient signserverRestClient;
    KeySpecificationParser keySpecificationParser;

    public SignserverClient(SignserverWSClient signserverWSClient, SignserverRestClient signserverRestClient,
                            KeySpecificationParser keySpecificationParser
    ) {
        this.signserverWSClient = signserverWSClient;
        this.signserverRestClient = signserverRestClient;
        this.keySpecificationParser = keySpecificationParser;
    }

    public void process(String workerName, String data, Map<String, String> metadata,
                        SignserverProcessEncoding encoding
    ) {
        signserverRestClient.process(workerName, data, metadata, encoding);
    }

    public Result<PKCS10CertificationRequest, ErrorWithDescription> generateCSR(int signerId, String keyAlias,
                                                                                String distinguishedName,
                                                                                String signatureAlgorithm
    ) {
        GetPKCS10CertificateRequestForAlias2Response response = signserverWSClient.generateCsr(signerId, keyAlias,
                                                                                               signatureAlgorithm,
                                                                                               distinguishedName
        );
        try {
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(response.getReturn().getBinary());
            return Result.ok(csr);
        } catch (IOException e) {
            return Result.error(new ErrorWithDescription("Error while parsing CSR", e.getMessage()));
        }
    }

    public Result<List<CryptoTokenKey>, ErrorWithDescription> queryCryptoTokenKeys(int cryptoTokenId, boolean includeData,
                                                                                   int startIndex, int numOfItems
    ) {
        try {
            var response = signserverWSClient.queryTokenEntries(cryptoTokenId, includeData, startIndex, numOfItems);
            var keyEntries = response.getReturn().getEntries();

            var keys = new ArrayList<CryptoTokenKey>();
            for (TokenEntry key: keyEntries) {
                var info = key.getInfo();
                var builder = new CryptoTokenKeyBuilder()
                        .withCryptoTokenId(cryptoTokenId)
                        .withKeyAlias(key.getAlias());

                info.getEntries().forEach(entry -> {
                    switch (entry.getKey()) {
                        case "Key specification" -> {
                            var keySpec = keySpecificationParser.parse(entry.getValue());
                            builder.withKeySpecification(keySpec.keySpecification())
                                   .withStatus(keySpec.keyStatus());
                        }
                        case "Key algorithm" -> builder.withKeyAlgorithm(entry.getValue());
                    }
                });
                keys.add(builder.build());
            }
            return Result.ok(keys);
        } catch (Exception e) {
            return Result.error(
                    new ErrorWithDescription("Failed to obtain keys of crypto token " + cryptoTokenId + ". ",
                                             e.getMessage()
                    ));
        }
    }

}
