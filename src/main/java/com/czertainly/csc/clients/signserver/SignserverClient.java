package com.czertainly.csc.clients.signserver;

import com.czertainly.csc.clients.signserver.rest.SignserverProcessEncoding;
import com.czertainly.csc.clients.signserver.rest.SignserverRestClient;
import com.czertainly.csc.clients.signserver.ws.SignserverWsClient;
import com.czertainly.csc.clients.signserver.ws.dto.CertReqData;
import com.czertainly.csc.clients.signserver.ws.dto.TokenEntry;
import com.czertainly.csc.common.exceptions.RemoteSystemException;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.crypto.CertificateParser;
import com.czertainly.csc.crypto.DigestAlgorithmJavaName;
import com.czertainly.csc.model.DocumentDigestsToSign;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.model.builders.CryptoTokenKeyBuilder;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.model.signserver.CryptoTokenKey;
import com.czertainly.csc.model.signserver.CryptoTokenKeyStatus;
import com.czertainly.csc.signing.Signature;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class SignserverClient {

    private static final Logger logger = LoggerFactory.getLogger(SignserverClient.class);
    SignserverWsClient signserverWSClient;
    SignserverRestClient signserverRestClient;
    KeySpecificationParser keySpecificationParser;
    ObjectMapper objectMapper;
    CertificateParser certificateParser;

    public SignserverClient(SignserverWsClient signserverWSClient, SignserverRestClient signserverRestClient,
                            KeySpecificationParser keySpecificationParser, ObjectMapper objectMapper,
                            CertificateParser certificateParser
    ) {
        this.signserverWSClient = signserverWSClient;
        this.signserverRestClient = signserverRestClient;
        this.keySpecificationParser = keySpecificationParser;
        this.objectMapper = objectMapper;
        this.certificateParser = certificateParser;
    }

    public Signature signSingleHash(String workerName, byte[] data, String keyAlias, String digestAlgorithm) {
        byte[] signatureBytes = singleSign(workerName, data, keyAlias, digestAlgorithm);
        Base64.Decoder decoder = Base64.getDecoder();
        return new Signature(decoder.decode(signatureBytes), SignaturePackaging.DETACHED);
    }

    private static List<Signature> mapToSignaturesList(BatchSignaturesResponse batchSignatures, Base64.Decoder decoder
    ) {
        List<Signature> signatures = new ArrayList<>();
        for (BatchSignatureResponse response : batchSignatures.signatures()) {
            signatures.add(new Signature(decoder.decode(response.signature()), SignaturePackaging.DETACHED));
        }
        return signatures;
    }

    public List<Signature> signMultipleHashes(String workerName, List<String> data, String keyAlias, String digestAlgorithm) {
        byte[] encodedSignatureData = multisign(workerName, data, keyAlias, digestAlgorithm);
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

    public SignedDocuments signSingleHashWithValidationData(String workerName, byte[] data, String keyAlias,
                                                            String digestAlgorithm
    ) {
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

    private byte[] singleSign(String workerName, byte[] data, String keyAlias, String digestAlgorithm) {
        var metadata = new HashMap<String, String>();
        metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", DigestAlgorithmJavaName.get(digestAlgorithm));

        // SignserverProcessEncoding.NONE is used as hash is already base64 encoded, so no need to encode it again
        return sign(workerName, data, keyAlias, metadata, SignserverProcessEncoding.NONE);
    }

    private byte[] multisign(String workerName, List<String> data, String keyAlias, String digestAlgorithm) {
        var signatureRequests = new ArrayList<BatchSignatureRequest>();
        int i = 0;

        for (String hash : data) {
            var signatureRequest = new BatchSignatureRequest(hash,
                                                             DigestAlgorithmJavaName.get(digestAlgorithm),
                                                             "r" + i
            );
            signatureRequests.add(signatureRequest);
        }

        var batchRequest = new BatchSignatureRequests(signatureRequests);
        var metadata = new HashMap<String, String>();
        metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
        metadata.put("USING_BATCHSIGNING", "true");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", DigestAlgorithmJavaName.get(digestAlgorithm));

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

    public SignedDocuments signMultipleHashesWithValidationData(
            String workerName, List<String> data, String keyAlias, String digestAlgorithm
    ) {
        byte[] encodedSignatureData = multisign(workerName, data, keyAlias, digestAlgorithm);
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

    // Returns the signed data encoded in base64
    public byte[] sign(String workerName, byte[] data, String keyAlias,
                       Map<String, String> metadata,
                       SignserverProcessEncoding encoding
    ) {
        metadata.put("ALIAS", keyAlias);
        var response = signserverRestClient.process(workerName, data, metadata, encoding);
        return response.data().getBytes();
    }


    public Result<byte[], TextError> generateCSR(CryptoToken cryptoToken, String keyAlias,
                                                 String distinguishedName,
                                                 String signatureAlgorithm
    ) {
        return signserverWSClient.generateCsr(cryptoToken.id(), keyAlias, signatureAlgorithm, distinguishedName)
                                 .map(CertReqData::getBinary);

    }

    public Result<List<CryptoTokenKey>, TextError> queryCryptoTokenKeys(CryptoToken cryptoToken,
                                                                        boolean includeData,
                                                                        int startIndex,
                                                                        int numOfItems,
                                                                        String keyAliasFilterPattern
    ) {
        return signserverWSClient
                .queryTokenEntries(cryptoToken.id(), includeData, startIndex, numOfItems, keyAliasFilterPattern)
                .flatMap(searchResult -> {
                    ArrayList<CryptoTokenKey> keys = new ArrayList<>();
                    for (TokenEntry key : searchResult.getEntries()) {
                        var info = key.getInfo();
                        var builder = new CryptoTokenKeyBuilder().withCryptoTokenId(cryptoToken)
                                                                 .withKeyAlias(key.getAlias());

                        if (key.getChain() != null && !key.getChain().isEmpty()) {
                            byte[] certData = key.getChain().getFirst();
                            var getCertificateResult = certificateParser.parseDerEncodedCertificate(certData);
                            if (getCertificateResult instanceof Error(var e)) {
                                return Result.error(e);
                            }
                            X509Certificate cert = getCertificateResult.unwrap();
                            String dn = cert.getSubjectX500Principal().getName();
                            if (dn.contains("L=_SignServer_DUMMY_CERT_")) {
                                builder.withStatus(new CryptoTokenKeyStatus(false));
                            } else {
                                builder.withStatus(new CryptoTokenKeyStatus(true));
                            }
                            builder.withChain(key.getChain());
                        } else {
                            builder.withStatus(new CryptoTokenKeyStatus(false));
                        }
                        if (includeData) {
                            info.getEntries().forEach(entry -> {
                                switch (entry.getKey()) {
                                    case "Key specification" -> {
                                        var keySpec = keySpecificationParser.parse(entry.getValue());
                                        builder.withKeySpecification(keySpec.keySpecification());
                                        if (keySpec.keyStatus() != null) {
                                            builder.withStatus(keySpec.keyStatus());
                                        }
                                    }
                                    case "Key algorithm" -> builder.withKeyAlgorithm(entry.getValue());
                                }
                            });
                        }

                        keys.add(builder.build());
                    }
                    return Result.success(keys);
                });
    }

    public Result<CryptoTokenKey, TextError> getCryptoTokenKey(CryptoToken cryptoToken, String keyAlias
    ) {
        return queryCryptoTokenKeys(cryptoToken, true, 0, 2, keyAlias)
                .flatMap(keys -> {
                    if (keys.isEmpty()) {
                        return Result.error(
                                TextError.of("Key with alias %s not found in crypto token %s", keyAlias, cryptoToken.name())
                        );
                    }
                    if (keys.size() > 1) {
                        return Result.error(
                                TextError.of("Multiple keys with the same alias found: " +
                                                     keys.stream()
                                                         .map(CryptoTokenKey::keyAlias)
                                                         .collect(Collectors.joining())
                                )
                        );
                    }
                    return Result.success(keys.getFirst());
                });
    }

    public Result<Void, TextError> importCertificateChain(CryptoToken cryptoToken, String keyAlias,
                                                          List<byte[]> chain
    ) {
        return signserverWSClient.importCertificateChain(cryptoToken.id(), keyAlias, chain);
    }

    public Result<String, TextError> generateKey(CryptoToken cryptoToken, String keyAlias,
                                                 String keyAlgorithm, String keySpec
    ) {
        return signserverWSClient.generateKey(cryptoToken.id(), keyAlias, keyAlgorithm, keySpec)
                                 .flatMap(partialAlias -> queryCryptoTokenKeys(cryptoToken, false, 0, 2,
                                                                               partialAlias + "%"
                                 ))
                                 .flatMap(this::extractKeyAlias);

    }

    public Result<Void, TextError> removeKey(int workerId, String keyAlias) {
        return signserverWSClient.removeKey(workerId, keyAlias, false);
    }

    public Result<Void, TextError> removeKeyOkIfNotExists(int workerId, String keyAlias) {
        return signserverWSClient.removeKey(workerId, keyAlias, true);
    }

    private Result<String, TextError> extractKeyAlias(List<CryptoTokenKey> keys) {
        if (keys.isEmpty()) {
            return Result.error(TextError.of("Newly generated key not found."));
        }
        if (keys.size() > 1) {
            return Result.error(
                    TextError.of("Multiple keys with the same alias found: " +
                                         keys.stream()
                                             .map(CryptoTokenKey::keyAlias)
                                             .collect(Collectors.joining())
                    ));

        }
        String alias = keys.getFirst().keyAlias();
        return Result.success(alias);
    }
}


