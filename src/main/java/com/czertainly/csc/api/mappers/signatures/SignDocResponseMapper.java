package com.czertainly.csc.api.mappers.signatures;

import com.czertainly.csc.api.signdoc.SignDocResponseDto;
import com.czertainly.csc.api.signdoc.ValidationInfo;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

@Component
public class SignDocResponseMapper{

    Base64.Encoder encoder = Base64.getEncoder();

    public Result<SignDocResponseDto, TextError> map(SignedDocuments model) {
        try {


            List<String> documentWithSignature = model.signatures().stream()
                                                      .filter(signature -> signature.packaging() != SignaturePackaging.DETACHED)
                                                      .map(signature -> encoder.encodeToString(signature.value()))
                                                      .toList();

            List<String> signatureObject = model.signatures().stream()
                                                .filter(signature -> signature.packaging() == SignaturePackaging.DETACHED)
                                                .map(signature -> encoder.encodeToString(signature.value()))
                                                .toList();

            ValidationInfo validationInfo = model.certs().isEmpty() && model.crls().isEmpty() && model.ocsps()
                                                                                                      .isEmpty() ?
                    null :
                    new ValidationInfo(
                            model.crls().stream().toList(),
                            model.ocsps().stream().toList(),
                            model.certs().stream().toList()
                    );

            return Result.success(new SignDocResponseDto(
                    documentWithSignature,
                    signatureObject,
                    null,
                    validationInfo
            )) ;
        } catch (Exception e) {
            return Result.error(TextError.of("Error while mapping signature to the response body. %s", e.getMessage()));
        }
    }
}
