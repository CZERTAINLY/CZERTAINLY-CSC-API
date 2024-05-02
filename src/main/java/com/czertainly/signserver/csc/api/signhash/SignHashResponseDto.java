package com.czertainly.signserver.csc.api.signhash;

import com.czertainly.signserver.csc.api.BaseSignatureResponseDto;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

public class SignHashResponseDto extends BaseSignatureResponseDto {

    @Schema(
            description = """
                    One or more Base64-encoded signed hash(s). In case of multiple signatures, the signed
                    hashes are returned in the same order as the corresponding hashes provided as
                    an input parameter. This value is returned when operationMode is `S`.
                    """
    )
    private final List<String> signatures;

    public SignHashResponseDto(List<String> signatures, String responseId) {
        super(responseId);
        this.signatures = signatures;
    }

    public List<String> getSignatures() {
        return signatures;
    }

}
