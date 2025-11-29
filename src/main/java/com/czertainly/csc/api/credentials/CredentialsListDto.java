package com.czertainly.csc.api.credentials;

import com.czertainly.csc.components.DateConverter;
import com.czertainly.csc.model.csc.Credential;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

public record CredentialsListDto(
        @Schema(
                description = """
                        One or more credentialID(s) associated with the provided or implicit userID.
                        """,
                implementation = List.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        List<String> credentialIDs,

        @Schema(
                description = """
                            The contents of credentialInfo object are described below. If the
                            credentialInfo parameter is not “true”, this value SHALL NOT be returned.
                        """,
                implementation = CredentialDto.class,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        List<CredentialDto> credentialInfos,

        @Schema(
                description = """
                            This value SHALL be returned true when the input parameter “onlyValid”
                            was true, and the RSSP supports this feature, i.e. the RSSP only returns
                            credentials which can be used for signing.
                            If the values is false or the output parameter is omitted, then the list may
                            contain credentials which cannot be used for signing.
                        """,
                implementation = CredentialDto.class,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        boolean onlyValid

) {
    static public CredentialsListDto from(List<Credential> credentials, DateConverter dateConverter) {
        return new CredentialsListDto(
                credentials.stream().map(Credential::credentialID).toList(),
                credentials.stream().map(c -> CredentialDto.fromModel(c, dateConverter)).toList(),
                false
        );
    }
}
