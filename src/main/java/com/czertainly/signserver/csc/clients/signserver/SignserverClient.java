package com.czertainly.signserver.csc.clients.signserver;

import com.czertainly.signserver.csc.clients.signserver.rest.SignserverProcessEncoding;
import com.czertainly.signserver.csc.clients.signserver.rest.SignserverRestClient;
import com.czertainly.signserver.csc.clients.signserver.ws.SignserverWsClient;
import com.czertainly.signserver.csc.clients.signserver.ws.dto.GetPKCS10CertificateRequestForAlias2Response;
import com.czertainly.signserver.csc.clients.signserver.ws.dto.TokenEntry;
import com.czertainly.signserver.csc.common.ErrorWithDescription;
import com.czertainly.signserver.csc.common.Result;
import com.czertainly.signserver.csc.crypto.DigestAlgorithmJavaName;
import com.czertainly.signserver.csc.model.DocumentDigestsToSign;
import com.czertainly.signserver.csc.model.builders.CryptoTokenKeyBuilder;
import com.czertainly.signserver.csc.model.signserver.CryptoTokenKey;
import com.czertainly.signserver.csc.signing.Signature;
import com.czertainly.signserver.csc.signing.configuration.SignaturePackaging;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;
import org.springframework.ws.soap.client.SoapFaultClientException;

import java.util.*;

@Component
public class SignserverClient {

    SignserverWsClient signserverWSClient;
    SignserverRestClient signserverRestClient;
    KeySpecificationParser keySpecificationParser;
    ObjectMapper objectMapper;

    public SignserverClient(SignserverWsClient signserverWSClient, SignserverRestClient signserverRestClient,
                            KeySpecificationParser keySpecificationParser, ObjectMapper objectMapper
    ) {
        this.signserverWSClient = signserverWSClient;
        this.signserverRestClient = signserverRestClient;
        this.keySpecificationParser = keySpecificationParser;
        this.objectMapper = objectMapper;
    }


    public Result<Signature, ErrorWithDescription> signSingleHash(String workerName, byte[] data, String keyAlias,
                                                                  String digestAlgorithm
    ) {
        var metadata = new HashMap<String, String>();
        metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", DigestAlgorithmJavaName.get(digestAlgorithm));
        try {
            // SignserverProcessEncoding.NONE is used as hash is already base64 encoded, so no need to encode it again
            Result<String, ErrorWithDescription> signatureResult = sign(workerName, data, keyAlias, metadata, SignserverProcessEncoding.NONE);
            if (signatureResult.isSuccess()) {
                return Result.ok(new Signature(signatureResult.getValue().getBytes(), SignaturePackaging.DETACHED));
            } else {
                return Result.error(new ErrorWithDescription("Failed to sign hash.", signatureResult.getError().error()));
            }
        } catch (Exception e) {
            return Result.error(new ErrorWithDescription("Error while signing data", e.getMessage()));
        }
    }

    public Result<List<Signature>, ErrorWithDescription> signMultipleHashes(String workerName, DocumentDigestsToSign digests,
                                                                   String keyAlias
    ) {
        var signatureRequests = new ArrayList<BatchSignatureRequest>();
        int i = 0;

        for (String hash : digests.hashes()) {
            var signatureRequest = new BatchSignatureRequest(hash, DigestAlgorithmJavaName.get(digests.digestAlgorithm()), "r" + i);
            signatureRequests.add(signatureRequest);
        }

        var batchRequest = new BatchSignatureRequests(signatureRequests);
        var metadata = new HashMap<String, String>();
        metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
        metadata.put("USING_BATCHSIGNING", "true");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", DigestAlgorithmJavaName.get(digests.digestAlgorithm()));
        try {
            var bytes = objectMapper.writeValueAsBytes(batchRequest);
            Result<String, ErrorWithDescription> signatureResult = sign(workerName, bytes, keyAlias, metadata, SignserverProcessEncoding.NONE);
            if (signatureResult.isSuccess()) {
                byte[] jsonBytes = Base64.getDecoder().decode(signatureResult.getValue());
                BatchSignaturesResponse batchSignatures = objectMapper.readValue(jsonBytes, BatchSignaturesResponse.class);
                List<Signature> signatures = new ArrayList<>();
                for (BatchSignatureResponse response : batchSignatures.signatures()) {
                    signatures.add(new Signature(response.signature().getBytes(), SignaturePackaging.DETACHED));
                }
                return Result.ok(signatures);
            } else {
                return Result.error(new ErrorWithDescription("Failed to sign hash.", signatureResult.getError().error()));
            }
        } catch (Exception e) {
            return Result.error(new ErrorWithDescription("Error while signing data", e.getMessage()));
        }
    }

    // Returns the signed data encoded in base64
    public Result<String, ErrorWithDescription> sign(String workerName, byte[] data, String keyAlias,
                                                     Map<String, String> metadata,
                                                     SignserverProcessEncoding encoding
    ) {
        metadata.put("ALIAS", keyAlias);
        try {
            var response = signserverRestClient.process(workerName, data, metadata, encoding);
            return Result.ok(response.data());
        } catch (Exception e) {
            return Result.error(new ErrorWithDescription("Error while signing data", e.getMessage()));
        }
    }


    public Result<byte[], ErrorWithDescription> generateCSR(int signerId, String keyAlias,
                                                            String distinguishedName,
                                                            String signatureAlgorithm
    ) {
        GetPKCS10CertificateRequestForAlias2Response response = signserverWSClient
                .generateCsr(signerId, keyAlias, signatureAlgorithm, distinguishedName);
        try {
            return Result.ok(response.getReturn().getBinary());
        } catch (SoapFaultClientException e) {
            return Result.error(new ErrorWithDescription("Error while parsing CSR", e.getMessage()));
        }
    }

    public Result<List<CryptoTokenKey>, ErrorWithDescription> queryCryptoTokenKeys(int cryptoTokenId,
                                                                                   boolean includeData,
                                                                                   int startIndex, int numOfItems
    ) {
        try {
            var response = signserverWSClient.queryTokenEntries(cryptoTokenId, includeData, startIndex, numOfItems);
            var keyEntries = response.getReturn().getEntries();

            var keys = new ArrayList<CryptoTokenKey>();
            for (TokenEntry key : keyEntries) {
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

    public Result<Void, ErrorWithDescription> importCertificateChain(int workerId, String keyAlias, byte[] chain) {
        try {
            signserverWSClient.importCertificateChain(workerId, keyAlias, chain);
            return Result.ok(null);
        } catch (Exception e) {
            return Result.error(
                    new ErrorWithDescription("Failed to import certificate chain for key " + keyAlias + ". ",
                                             e.getMessage()
                    ));
        }
    }

}
