package com.czertainly.csc.api.mappers.signatures;

import com.czertainly.csc.api.signdoc.SignDocResponseDto;
import com.czertainly.csc.api.signdoc.ValidationInfo;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.DocumentSignature;
import com.czertainly.csc.model.SignaturesContainer;
import com.czertainly.csc.model.SignaturesWithValidationInfo;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

@Component
public class SignDocResponseMapper {

    Base64.Encoder encoder = Base64.getEncoder();

    public Result<SignDocResponseDto, TextError> map(SignaturesContainer<DocumentSignature> model) {
        try {
            List<String> documentWithSignature = model.signatures().stream()
                                                      .filter(signature -> signature.packaging() != SignaturePackaging.DETACHED)
                                                      .map(signature -> encoder.encodeToString(signature.value()))
                                                      .toList();

            List<String> signatureObject = model.signatures().stream()
                                                .filter(signature -> signature.packaging() == SignaturePackaging.DETACHED)
                                                .map(signature -> encoder.encodeToString(signature.value()))
                                                .toList();

            ValidationInfo validationInfo = null;
            if (model instanceof SignaturesWithValidationInfo<DocumentSignature> swvi) {
                validationInfo = new ValidationInfo(swvi.crls(), swvi.ocsps(), swvi.certs());
            }

            return Result.success(new SignDocResponseDto(
                    documentWithSignature,
                    signatureObject,
                    null,
                    validationInfo
            ));
        } catch (Exception e) {
            return Result.error(TextError.of("Error while mapping signature to the response body. %s", e.getMessage()));
        }
    }
}
