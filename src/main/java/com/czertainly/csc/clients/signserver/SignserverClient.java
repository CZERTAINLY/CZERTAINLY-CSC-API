package com.czertainly.csc.clients.signserver;

import com.czertainly.csc.clients.signserver.rest.SignserverProcessEncoding;
import com.czertainly.csc.clients.signserver.rest.SignserverRestClient;
import com.czertainly.csc.clients.signserver.ws.SignserverWsClient;
import com.czertainly.csc.clients.signserver.ws.dto.CertReqData;
import com.czertainly.csc.clients.signserver.ws.dto.TokenEntry;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.crypto.CertificateParser;
import com.czertainly.csc.crypto.DigestAlgorithmJavaName;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.model.builders.CryptoTokenKeyBuilder;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.model.signserver.CryptoTokenKey;
import com.czertainly.csc.model.signserver.CryptoTokenKeyStatus;
import com.czertainly.csc.signing.Signature;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
    private final SignserverWsClient signserverWSClient;
    private final SignserverRestClient signserverRestClient;
    private final KeySpecificationParser keySpecificationParser;
    private final ObjectMapper objectMapper;
    private final CertificateParser certificateParser;

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

    public Result<Signature, TextError> signSingleHash(
            String workerName, byte[] data, String keyAlias, String digestAlgorithm
    ) {
        Base64.Decoder decoder = Base64.getDecoder();
        return singleSign(workerName, data, keyAlias, digestAlgorithm)
                .flatMap(encodedSignatures -> base64Decode(decoder, encodedSignatures))
                .map(signatureBytes -> new Signature(signatureBytes, SignaturePackaging.DETACHED));
    }

    public Result<SignedDocuments, TextError> signSingleHashWithValidationData(
            String workerName, byte[] data, String keyAlias, String digestAlgorithm
    ) {
        Base64.Decoder decoder = Base64.getDecoder();
        return singleSign(workerName, data, keyAlias, digestAlgorithm)
                .flatMap(encodedSignatures -> base64Decode(decoder, encodedSignatures))
                .flatMap(decodedSignatures -> mapToObject(
                        decoder, decodedSignatures, EncodedValidationDataWrapper.class
                ))
                .flatMap(signatureWithValidationData ->
                                 base64Decode(decoder, signatureWithValidationData.signatureData().getBytes())
                                         .map(signatureBytes -> new SignedDocuments(
                                                 List.of(new Signature(signatureBytes, SignaturePackaging.DETACHED)),
                                                 new HashSet<>(signatureWithValidationData.validationData().crl()),
                                                 new HashSet<>(signatureWithValidationData.validationData().ocsp()),
                                                 new HashSet<>(
                                                         signatureWithValidationData.validationData().certificates())
                                         ))
                );
    }

    public Result<List<Signature>, TextError> signMultipleHashes(String workerName, List<String> data, String keyAlias,
                                                                 String digestAlgorithm
    ) {
        Base64.Decoder decoder = Base64.getDecoder();
        return multisign(workerName, data, keyAlias, digestAlgorithm)
                .flatMap(encodedSignatures -> base64Decode(decoder, encodedSignatures))
                .flatMap(decodedSignatures -> mapToObject(decoder, decodedSignatures, BatchSignaturesResponse.class))
                .map(batchSignatures -> mapToSignaturesList(batchSignatures, decoder));
    }

    public Result<SignedDocuments, TextError> signMultipleHashesWithValidationData(
            String workerName, List<String> data, String keyAlias, String digestAlgorithm
    ) {
        Base64.Decoder decoder = Base64.getDecoder();
        return multisign(workerName, data, keyAlias, digestAlgorithm)
                .flatMap(encodedSignatures -> base64Decode(decoder, encodedSignatures))
                .flatMap(decodedSignatures -> mapToObject(decoder, decodedSignatures,
                                                          BatchSignatureWithValidationData.class
                ))
                .map(batchSignatures -> {
                    List<Signature> signatures = mapToSignaturesList(batchSignatures.signatureData(), decoder);
                    return new SignedDocuments(
                            signatures,
                            new HashSet<>(batchSignatures.validationData().crl()),
                            new HashSet<>(batchSignatures.validationData().ocsp()),
                            new HashSet<>(batchSignatures.validationData().certificates())
                    );
                });
    }

    public Result<byte[], TextError> generateCSR(
            CryptoToken cryptoToken, String keyAlias, String distinguishedName, String signatureAlgorithm
    ) {
        return signserverWSClient.generateCsr(cryptoToken.id(), keyAlias, signatureAlgorithm, distinguishedName)
                                 .map(CertReqData::getBinary);

    }

    public Result<List<CryptoTokenKey>, TextError> queryCryptoTokenKeys(
            CryptoToken cryptoToken, boolean includeData, int startIndex, int numOfItems, String keyAliasFilterPattern
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

    public Result<Void, TextError> importCertificateChain(
            CryptoToken cryptoToken, String keyAlias, List<byte[]> chain
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

    private Result<byte[], TextError> singleSign(
            String workerName, byte[] data, String keyAlias, String digestAlgorithm
    ) {
        var metadata = new HashMap<String, String>();
        metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", DigestAlgorithmJavaName.get(digestAlgorithm));

        // SignserverProcessEncoding.NONE is used as hash is already base64 encoded, so no need to encode it again
        return sign(workerName, data, keyAlias, metadata, SignserverProcessEncoding.NONE);
    }

    private Result<byte[], TextError> multisign(String workerName, List<String> data, String keyAlias,
                                                String digestAlgorithm
    ) {
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

    // Returns the signed data encoded in base64
    private Result<byte[], TextError> sign(String workerName, byte[] data, String keyAlias,
                        Map<String, String> metadata,
                        SignserverProcessEncoding encoding
    ) {
        metadata.put("ALIAS", keyAlias);
        return signserverRestClient.process(workerName, data, metadata, encoding)
                                   .map(response -> response.data().getBytes());
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

    private Result<byte[], TextError> base64Decode(Base64.Decoder decoder, byte[] encodedSignatureData) {
        try {
            byte[] decoded = decoder.decode(encodedSignatureData);
            return Result.success(decoded);
        } catch (IllegalArgumentException e) {
            logger.error("The decoding of the signature data has failed.", e);
            return Result.error(TextError.of("The decoding of the signature data has failed."));
        }
    }

    private <T> Result<T, TextError> mapToObject(Base64.Decoder decoder, byte[] encodedSignatureData, Class<T> clazz) {
        try {
            byte[] decoded = decoder.decode(encodedSignatureData);
            return Result.success(objectMapper.readValue(decoded, clazz));
        } catch (IOException e) {
            logger.error("Decoding of the signature data to object has failed.", e);
            return Result.error(TextError.of("The decoding of the signature data has failed."));
        }
    }

    private static List<Signature> mapToSignaturesList(BatchSignaturesResponse batchSignatures, Base64.Decoder decoder
    ) {
        List<Signature> signatures = new ArrayList<>();
        for (BatchSignatureResponse response : batchSignatures.signatures()) {
            signatures.add(new Signature(decoder.decode(response.signature()), SignaturePackaging.DETACHED));
        }
        return signatures;
    }
}


