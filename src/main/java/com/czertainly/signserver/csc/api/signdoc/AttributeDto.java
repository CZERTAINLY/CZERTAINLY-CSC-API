package com.czertainly.signserver.csc.api.signdoc;

import com.czertainly.signserver.csc.signing.configuration.AttributeName;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

public record AttributeDto(

        @JsonProperty("attribute_name")
        @Schema(
                description = """
                        Name or OID of the attribute/property to be included in the signature.
                        """,
                implementation = AttributeName.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String name,

        @JsonProperty("attribute_value")
        @Schema(
                description = """
                        Value of the attribute/property to be included in the signature. The value depends on
                        the attribute/property specified in `attribute_name`.
                        """
        )
        String value
) {
}
