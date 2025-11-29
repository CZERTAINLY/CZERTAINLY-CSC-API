package com.czertainly.csc.api.mappers.signatures;

import com.czertainly.csc.api.signhash.SignHashResponseDto;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.PlainSignature;
import com.czertainly.csc.model.SignaturesContainer;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

@Component
public class SignHashResponseMapper {

    Base64.Encoder encoder = Base64.getEncoder();

    public Result<SignHashResponseDto, TextError> map(SignaturesContainer<PlainSignature> model) {
        try {
            List<String> encodedSignatures = model.signatures().stream()
                                                  .map(signature -> encoder.encodeToString(signature.value()))
                                                  .toList();


            return Result.success(
                    new SignHashResponseDto(encodedSignatures, null)
            );
        } catch (Exception e) {
            return Result.error(
                    TextError.of("Error while mapping signatures to the response body. %s", e.getMessage()));
        }
    }
}
