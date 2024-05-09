package com.czertainly.signserver.csc.clients.signserver;

import com.czertainly.signserver.csc.clients.signserver.rest.SignserverProcessEncoding;
import com.czertainly.signserver.csc.clients.signserver.rest.SignserverRestClient;
import com.czertainly.signserver.csc.clients.signserver.ws.SignserverWsClient;
import com.czertainly.signserver.csc.clients.signserver.ws.dto.CertReqData;
import com.czertainly.signserver.csc.clients.signserver.ws.dto.TokenEntry;
import com.czertainly.signserver.csc.clients.signserver.ws.dto.TokenSearchResults;
import com.czertainly.signserver.csc.common.exceptions.RemoteSystemException;
import com.czertainly.signserver.csc.crypto.DigestAlgorithmJavaName;
import com.czertainly.signserver.csc.model.DocumentDigestsToSign;
import com.czertainly.signserver.csc.model.SignedDocuments;
import com.czertainly.signserver.csc.model.builders.CryptoTokenKeyBuilder;
import com.czertainly.signserver.csc.model.signserver.CryptoTokenKey;
import com.czertainly.signserver.csc.signing.Signature;
import com.czertainly.signserver.csc.signing.configuration.SignaturePackaging;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
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

    public Signature signSingleHash(String workerName, byte[] data, String keyAlias, String digestAlgorithm) {
        byte[] signatureBytes = singleSign(workerName, data, keyAlias, digestAlgorithm);
        Base64.Decoder decoder = Base64.getDecoder();
        return new Signature(decoder.decode(signatureBytes), SignaturePackaging.DETACHED);
    }

    public SignedDocuments signSingleHashWithValidationData(String workerName, byte[] data, String keyAlias, String digestAlgorithm) {
        byte[] signatureWithValidationData = singleSign(workerName, data, keyAlias, digestAlgorithm);
        Base64.Decoder decoder = Base64.getDecoder();

        byte[] signatureData = decoder.decode(signatureWithValidationData);
        EncodedValidationDataWrapper validationDataWrapper;
        try {
            validationDataWrapper = objectMapper.readValue(
                    signatureData,
                    EncodedValidationDataWrapper.class
            );
        } catch (IOException e) {
            throw new RemoteSystemException("Signserver batch signature response could not be parsed.", e);
        }
        byte[] signatureBytes = decoder.decode(validationDataWrapper.signatureData().getBytes());

        return new SignedDocuments(
                List.of(new Signature(signatureBytes, SignaturePackaging.DETACHED)),
                new HashSet<>(validationDataWrapper.validationData().crl()),
                new HashSet<>(validationDataWrapper.validationData().ocsp()),
                new HashSet<>(validationDataWrapper.validationData().certificates())
        );
    }

    public List<Signature> signMultipleHashes(String workerName, DocumentDigestsToSign digests, String keyAlias) {
        byte[] encodedSignatureData = multisign(workerName, digests, keyAlias);
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] signatureData = decoder.decode(encodedSignatureData);

        BatchSignaturesResponse batchSignatures;
        try {
            batchSignatures = objectMapper.readValue(
                    signatureData,
                    BatchSignaturesResponse.class
            );
        } catch (IOException e) {
            throw new RemoteSystemException("Signserver batch signature response could not be parsed.", e);
        }
        return mapToSignaturesList(batchSignatures, decoder);
    }

    public SignedDocuments signMultipleHashesWithValidationData(String workerName, DocumentDigestsToSign digests, String keyAlias) {
        byte[] encodedSignatureData = multisign(workerName, digests, keyAlias);
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] signatureData = decoder.decode(encodedSignatureData);

        BatchSignatureWithValidationData batchSignaturesWithValidationData;
        try {
            batchSignaturesWithValidationData = objectMapper.readValue(
                    signatureData,
                    BatchSignatureWithValidationData.class
            );
        } catch (IOException e) {
            throw new RemoteSystemException("Signserver batch signature response could not be parsed.", e);
        }
        List<Signature> signatures = mapToSignaturesList(batchSignaturesWithValidationData.signatureData(), decoder);
        return new SignedDocuments(
                signatures,
                new HashSet<>(batchSignaturesWithValidationData.validationData().crl()),
                new HashSet<>(batchSignaturesWithValidationData.validationData().ocsp()),
                new HashSet<>(batchSignaturesWithValidationData.validationData().certificates())
        );
    }

    private byte[] singleSign(String workerName, byte[] data, String keyAlias, String digestAlgorithm) {
        var metadata = new HashMap<String, String>();
        metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", DigestAlgorithmJavaName.get(digestAlgorithm));

        // SignserverProcessEncoding.NONE is used as hash is already base64 encoded, so no need to encode it again
        return sign(workerName, data, keyAlias, metadata, SignserverProcessEncoding.NONE);
    }

    private byte[] multisign(String workerName, DocumentDigestsToSign digests, String keyAlias) {
        var signatureRequests = new ArrayList<BatchSignatureRequest>();
        int i = 0;

        for (String hash : digests.hashes()) {
            var signatureRequest = new BatchSignatureRequest(hash,
                                                             DigestAlgorithmJavaName.get(digests.digestAlgorithm()),
                                                             "r" + i
            );
            signatureRequests.add(signatureRequest);
        }

        var batchRequest = new BatchSignatureRequests(signatureRequests);
        var metadata = new HashMap<String, String>();
        metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
        metadata.put("USING_BATCHSIGNING", "true");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", DigestAlgorithmJavaName.get(digests.digestAlgorithm()));

        final byte[] requestBytes;
        try {
            requestBytes = objectMapper.writeValueAsBytes(batchRequest);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Serialization of batch signature request has failed.", e);
        }

        return sign(workerName, requestBytes, keyAlias, metadata,
                    SignserverProcessEncoding.NONE
        );
    }

    private static List<Signature> mapToSignaturesList(BatchSignaturesResponse batchSignatures, Base64.Decoder decoder) {
        List<Signature> signatures = new ArrayList<>();
        for (BatchSignatureResponse response : batchSignatures.signatures()) {
            signatures.add(new Signature(decoder.decode(response.signature()), SignaturePackaging.DETACHED));
        }
        return signatures;
    }

    // Returns the signed data encoded in base64
    public byte[] sign(String workerName, byte[] data, String keyAlias,
                       Map<String, String> metadata,
                       SignserverProcessEncoding encoding
    ) {
        metadata.put("ALIAS", keyAlias);
        var response = signserverRestClient.process(workerName, data, metadata, encoding);
        return response.data().getBytes();
    }


    public byte[] generateCSR(int signerId, String keyAlias, String distinguishedName, String signatureAlgorithm) {
        CertReqData response = signserverWSClient
                .generateCsr(signerId, keyAlias, signatureAlgorithm, distinguishedName);

        return response.getBinary();
    }

    public List<CryptoTokenKey> queryCryptoTokenKeys(int cryptoTokenId, boolean includeData, int startIndex,
                                                    int numOfItems
    ) {
        TokenSearchResults searchResult = signserverWSClient.queryTokenEntries(cryptoTokenId, includeData,
                                                                               startIndex, numOfItems
        );

        ArrayList<CryptoTokenKey> keys = new ArrayList<>();
        for (TokenEntry key : searchResult.getEntries()) {
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
        return keys;
    }

    public void importCertificateChain(int workerId, String keyAlias, byte[] chain) {
        signserverWSClient.importCertificateChain(workerId, keyAlias, chain);
    }

    public void removeKey(int workerId, String keyAlias) {
        boolean removed = signserverWSClient.removeKey(workerId, keyAlias);
        if (!removed) {
            throw new RemoteSystemException("Failed to remove key " + keyAlias + " from crypto token " + workerId);
        }
    }

}
