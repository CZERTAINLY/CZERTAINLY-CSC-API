package com.czertainly.csc.api.mappers.signatures;

import com.czertainly.csc.api.OperationMode;
import com.czertainly.csc.api.auth.SADParser;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.signdoc.DocumentDigestsDto;
import com.czertainly.csc.api.signdoc.DocumentDto;
import com.czertainly.csc.api.signdoc.SignDocRequestDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.crypto.AlgorithmPair;
import com.czertainly.csc.crypto.AlgorithmUnifier;
import com.czertainly.csc.model.DocumentDigestsToSign;
import com.czertainly.csc.model.DocumentToSign;
import com.czertainly.csc.model.SignDocParameters;
import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.UUID;

@Component
public class SignDocValidatingRequestMapper {

    AlgorithmUnifier algorithmUnifier;
    SADParser sadParser;


    public SignDocValidatingRequestMapper(AlgorithmUnifier algorithmUnifier, SADParser sadParser) {
        this.algorithmUnifier = algorithmUnifier;
        this.sadParser = sadParser;
    }

    public SignDocParameters map(SignDocRequestDto dto, SignatureActivationData sad) {
        if (dto == null) throw InvalidInputDataException.of("Missing request parameters.");

        if (dto.getCredentialID().isEmpty() && dto.getSignatureQualifier().isEmpty()) {
            throw InvalidInputDataException.of(
                    "Empty credentialID and signatureQualifier. At least one of them must be provided.");
        }

        final String credentialId = dto.getCredentialID().orElse(null);

        final UUID credentialIdUUID;
        try {
            if (credentialId != null) {
                credentialIdUUID = UUID.fromString(credentialId);
            }
            else {
                credentialIdUUID = null;
            }
        } catch (IllegalArgumentException e) {
            throw InvalidInputDataException.of("Invalid string parameter SAD");
        }

        final String signatureQualifier = dto.getSignatureQualifier().orElse(null);

        if (dto.getSAD().isEmpty() && sad == null) {
            throw InvalidInputDataException.of("Missing (or invalid type) string parameter SAD");
        } else if (dto.getSAD().isPresent() && sad != null) {
            throw InvalidInputDataException.of("Signature activation data was provided in both the request" +
                                                 " and the access token. Please provide it only at one place.");
        } else if (dto.getSAD().isPresent()) {
            String sadString = dto.getSAD().get();
            sad = sadParser.parse(sadString);
        }

        final List<DocumentToSign> documentsToSign;
        final List<DocumentDigestsToSign> documentDigestsToSign;
        if (dto.getDocuments().isEmpty() && dto.getDocumentDigests().isEmpty()) {
            throw InvalidInputDataException.of("Empty documentDigests and documents objects");
        } else if (!dto.getDocuments().isEmpty() && !dto.getDocumentDigests().isEmpty()) {
            throw InvalidInputDataException.of("Both documentDigests and documents parameters passed");
        }

            documentsToSign = dto.getDocuments().stream()
                                 .map(this::mapDocument)
                                 .toList();
            documentDigestsToSign = dto.getDocumentDigests().stream()
                                 .map(this::mapDocumentDigests)
                                 .toList();

        final String operationModeString = dto.getOperationMode().orElse("S");
        final OperationMode operationMode;
        if (operationModeString.equals("S")) {
            operationMode = OperationMode.SYNCHRONOUS;
        } else if (operationModeString.equals("A")) {
            throw InvalidInputDataException.of("Asynchronous operation mode is not yet supported.");
//            operationMode = OperationMode.ASYNCHRONOUS;
        } else {
            throw InvalidInputDataException.of("Invalid parameter operationMode.");
        }

        final String clientData = dto.getClientData().orElse("");
        final boolean returnValidationInfo = dto.getReturnValidationInfo().orElse(false);


        return new SignDocParameters(
                        operationMode,
                        documentsToSign,
                        documentDigestsToSign,
                        credentialIdUUID,
                        signatureQualifier,
                        sad,
                        clientData,
                        returnValidationInfo
        );
    }

    private DocumentToSign mapDocument(DocumentDto dto) {
        final String document;
        if (dto.getDocument().isEmpty()) {
            throw new InvalidInputDataException("Invalid Base64 documents string parameter");
        }
        document = dto.getDocument().get();

        final SignatureFormat signatureFormat;
        if (dto.getSignatureFormat().isEmpty()) {
            throw new InvalidInputDataException("Missing (or invalid type) string parameter signature_format");
        }
        signatureFormat = SignatureFormat.fromString(dto.getSignatureFormat().get());

        ConformanceLevel conformanceLevel = ConformanceLevel.fromString(dto.getConformanceLevel().orElse("Ades-B-B"));

        if (dto.getSignAlgo().isEmpty()) {
            throw new InvalidInputDataException("Missing (or invalid type) string parameter signAlgo");
        }

        AlgorithmPair algorithmPair = algorithmUnifier
                .unify(dto.getSignAlgo().get(), null)
                .consumeError(e -> {throw new InvalidInputDataException(e.toString());})
                .unwrap();
        final String keyAlgo = algorithmPair.keyAlgo();
        final String digestAlgo = algorithmPair.digestAlgo();

        final String signAlgoParams = dto.getSignAlgoParams().orElse(null);

        SignaturePackaging signaturePackaging;
        if (dto.getSignaturePackaging().isEmpty()) {
            signaturePackaging = switch (signatureFormat) {
                case SignatureFormat.CAdES, SignatureFormat.JAdEs -> SignaturePackaging.ATTACHED;
                case SignatureFormat.PAdES -> SignaturePackaging.CERTIFICATION;
                case SignatureFormat.XAdES -> SignaturePackaging.ENVELOPED;
            };
        } else {
            signaturePackaging = SignaturePackaging.fromString(dto.getSignaturePackaging().get());
        }

        // TODO: Implement signedAttributes
        return new DocumentToSign(document, signatureFormat, conformanceLevel, keyAlgo, digestAlgo, signAlgoParams,
                                  new HashMap<>(), signaturePackaging
        );
    }

    private DocumentDigestsToSign mapDocumentDigests(DocumentDigestsDto dto) {
        final List<String> hashes;
        if (dto.getHashes().isEmpty()) {
            throw new IllegalArgumentException("Invalid Base64 hashes string parameter");
        }
        hashes = dto.getHashes().get();


        final SignatureFormat signatureFormat;
        if (dto.getSignatureFormat().isEmpty()) {
            throw new IllegalArgumentException("Missing (or invalid type) string parameter signature_format");
        }
        signatureFormat = SignatureFormat.fromString(dto.getSignatureFormat().get());

        ConformanceLevel conformanceLevel = ConformanceLevel.fromString(dto.getConformanceLevel().orElse("Ades-B-B"));

        if (dto.getSignAlgo().isEmpty()) {
            throw new IllegalArgumentException("Missing (or invalid type) string parameter signAlgo");
        }

        AlgorithmPair algorithmPair = algorithmUnifier
                .unify(dto.getSignAlgo().get(), dto.getHashAlgorithmOID().orElse(null))
                .consumeError(e -> {throw new InvalidInputDataException(e.toString());})
                .unwrap();
        final String keyAlgo = algorithmPair.keyAlgo();
        final String digestAlgo = algorithmPair.digestAlgo();

        final String signAlgoParams = dto.getSignAlgoParams().orElse(null);

        SignaturePackaging signaturePackaging;
        if (dto.getSignaturePackaging().isEmpty()) {
            signaturePackaging = switch (signatureFormat) {
                case SignatureFormat.CAdES, SignatureFormat.JAdEs -> SignaturePackaging.ATTACHED;
                case SignatureFormat.PAdES -> SignaturePackaging.CERTIFICATION;
                case SignatureFormat.XAdES -> SignaturePackaging.ENVELOPED;
            };
        } else {
            signaturePackaging = SignaturePackaging.fromString(dto.getSignaturePackaging().get());
        }

        // TODO: Implement signedAttributes
        return new DocumentDigestsToSign(hashes, signatureFormat, conformanceLevel, keyAlgo, digestAlgo, signAlgoParams,
                                  new HashMap<>(), signaturePackaging
        );
    }
}
