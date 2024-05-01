package com.czertainly.signserver.csc.model.mappers;

import com.czertainly.signserver.csc.api.OperationMode;
import com.czertainly.signserver.csc.api.auth.SADParser;
import com.czertainly.signserver.csc.api.auth.SignatureActivationData;
import com.czertainly.signserver.csc.api.signdoc.DocumentDto;
import com.czertainly.signserver.csc.api.signdoc.SignDocRequestDto;
import com.czertainly.signserver.csc.api.signdoc.DocumentDigestsDto;
import com.czertainly.signserver.csc.common.result.ErrorWithDescription;
import com.czertainly.signserver.csc.common.result.Result;
import com.czertainly.signserver.csc.crypto.AlgorithmPair;
import com.czertainly.signserver.csc.crypto.AlgorithmUnifier;
import com.czertainly.signserver.csc.model.DocumentDigestsToSign;
import com.czertainly.signserver.csc.model.DocumentToSign;
import com.czertainly.signserver.csc.model.SignDocParameters;
import com.czertainly.signserver.csc.signing.configuration.ConformanceLevel;
import com.czertainly.signserver.csc.signing.configuration.SignatureFormat;
import com.czertainly.signserver.csc.signing.configuration.SignaturePackaging;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;

import static com.czertainly.signserver.csc.api.ErrorCodes.INVALID_REQUEST;


@Component
public class SignDocValidatingRequestMapper implements SignatureRequestMapper<SignDocRequestDto, SignDocParameters> {

    AlgorithmUnifier algorithmUnifier;
    SADParser sadParser;


    public SignDocValidatingRequestMapper(AlgorithmUnifier algorithmUnifier, SADParser sadParser) {
        this.algorithmUnifier = algorithmUnifier;
        this.sadParser = sadParser;
    }

    @Override
    public Result<SignDocParameters, ErrorWithDescription> map(SignDocRequestDto dto, SignatureActivationData sad) {
        if (dto == null) return toInvalidRequestError("Missing request parameters.");

        if (dto.getCredentialID().isEmpty() && dto.getSignatureQualifier().isEmpty()) {
            return toInvalidRequestError(
                    "Empty credentialID and signatureQualifier. At least one of them must be provided.");
        }

        final String credentialId = dto.getCredentialID().orElse(null);
        final String signatureQualifier = dto.getSignatureQualifier().orElse(null);

        if (dto.getSAD().isEmpty() && sad == null) {
            return toInvalidRequestError("Missing (or invalid type) string parameter SAD");
        } else if (dto.getSAD().isPresent() && sad != null) {
            return toInvalidRequestError("Signature activation data was provided in both the request" +
                                                 " and the access token. Please provide it in only one place.");
        } else if (dto.getSAD().isPresent()) {
            String sadString = dto.getSAD().get();
            sad = sadParser.parse(sadString);
        }

        final List<DocumentToSign> documentsToSign;
        final List<DocumentDigestsToSign> documentDigestsToSign;
        if (dto.getDocuments().isEmpty() && dto.getDocumentDigests().isEmpty()) {
            return toInvalidRequestError("Empty documentDigests and documents objects");
        } else if (!dto.getDocuments().isEmpty() && !dto.getDocumentDigests().isEmpty()) {
            return toInvalidRequestError("Both documentDigests and documents parameters passed");
        }

        try {
            documentsToSign = dto.getDocuments().stream()
                                 .map(this::mapDocument)
                                 .toList();
        } catch (IllegalArgumentException e) {
            return toInvalidRequestError(e.getMessage());
        }
        try {
            documentDigestsToSign = dto.getDocumentDigests().stream()
                                 .map(this::mapDocumentDigests)
                                 .toList();
        } catch (IllegalArgumentException e) {
            return toInvalidRequestError(e.getMessage());
        }

        final String operationModeString = dto.getOperationMode().orElse("S");
        final OperationMode operationMode;
        if (operationModeString.equals("S")) {
            operationMode = OperationMode.SYNCHRONOUS;
        } else if (operationModeString.equals("A")) {
            return toInvalidRequestError("Asynchronous operation mode is not yet supported.");
//            operationMode = OperationMode.ASYNCHRONOUS;
        } else {
            return toInvalidRequestError("Invalid parameter operationMode.");
        }

        final String clientData = dto.getClientData().orElse("");
        final boolean returnValidationInfo = dto.getReturnValidationInfo().orElse(false);


        return Result.ok(
                new SignDocParameters(
                        operationMode,
                        documentsToSign,
                        documentDigestsToSign,
                        credentialId,
                        signatureQualifier,
                        sad,
                        clientData,
                        returnValidationInfo
                )
        );
    }

    private DocumentToSign mapDocument(DocumentDto dto) {
        final String document;
        if (dto.getDocument().isEmpty()) {
            throw new IllegalArgumentException("Invalid Base64 documents string parameter");
        }
        document = dto.getDocument().get();

        final SignatureFormat signatureFormat;
        if (dto.getSignatureFormat().isEmpty()) {
            throw new IllegalArgumentException("Missing (or invalid type) string parameter signature_format");
        }
        signatureFormat = SignatureFormat.fromString(dto.getSignatureFormat().get());

        ConformanceLevel conformanceLevel = ConformanceLevel.fromString(dto.getConformanceLevel().orElse("Ades-B-B"));

        if (dto.getSignAlgo().isEmpty()) {
            throw new IllegalArgumentException("Missing (or invalid type) string parameter signAlgo");
        }

        final String keyAlgo;
        final String digestAlgo;
        Result<AlgorithmPair, ErrorWithDescription> result = algorithmUnifier.unify(dto.getSignAlgo().get(), null);

        if (result.isError()) {
            throw new IllegalArgumentException(result.getError().description());
        } else {
            AlgorithmPair algorithmPair = result.getValue();
            keyAlgo = algorithmPair.keyAlgo();
            digestAlgo = algorithmPair.digestAlgo();
        }

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

        final String keyAlgo;
        final String digestAlgo;
        Result<AlgorithmPair, ErrorWithDescription> result = algorithmUnifier
                .unify(dto.getSignAlgo().get(), dto.getHashAlgorithmOID().orElse(null));

        if (result.isError()) {
            throw new IllegalArgumentException(result.getError().description());
        } else {
            AlgorithmPair algorithmPair = result.getValue();
            keyAlgo = algorithmPair.keyAlgo();
            digestAlgo = algorithmPair.digestAlgo();
        }

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

    private Result<SignDocParameters, ErrorWithDescription> toInvalidRequestError(String errorMessage) {
        return Result.error(new ErrorWithDescription(INVALID_REQUEST, errorMessage));
    }

}
