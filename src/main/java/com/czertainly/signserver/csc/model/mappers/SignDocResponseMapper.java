package com.czertainly.signserver.csc.model.mappers;

import com.czertainly.signserver.csc.api.signdoc.SignDocResponseDto;
import com.czertainly.signserver.csc.api.signdoc.ValidationInfo;
import com.czertainly.signserver.csc.common.ErrorWithDescription;
import com.czertainly.signserver.csc.common.Result;
import com.czertainly.signserver.csc.model.SignedDocuments;
import com.czertainly.signserver.csc.signing.configuration.SignaturePackaging;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

@Component
public class SignDocResponseMapper implements SignatureResponseMapper<SignedDocuments, SignDocResponseDto> {

    Base64.Encoder encoder = Base64.getEncoder();

    @Override
    public Result<SignDocResponseDto, ErrorWithDescription> map(SignedDocuments model) {

        List<String> documentWithSignature = model.signatures().stream()
                                                  .filter(signature -> signature.packaging() != SignaturePackaging.DETACHED)
                                                  .map(signature -> encoder.encodeToString(signature.value()))
                                                  .toList();

        List<String> signatureObject = model.signatures().stream()
                                            .filter(signature -> signature.packaging() == SignaturePackaging.DETACHED)
                                            .map(signature -> encoder.encodeToString(signature.value()))
                                            .toList();

        ValidationInfo validationInfo = model.certs().isEmpty() && model.crls().isEmpty() && model.ocsps().isEmpty() ?
                null :
                new ValidationInfo(
                        model.crls().stream().toList(),
                        model.ocsps().stream().toList(),
                        model.certs().stream().toList()
                );

        return Result.ok(
                new SignDocResponseDto(
                        documentWithSignature,
                        signatureObject,
                        validationInfo
                )
        );
    }
}
