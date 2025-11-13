package com.czertainly.csc.api.info;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

public record SignatureFormatsDto(
        @Schema(description = """
                The list of signature formats supported by the remote service.
                """,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        List<String> formats,
        @Schema(description = """
                The list of the properties concerning the signed envelope, whose possible
                values depend on the value of the formats parameter entries, as defined in the
                Input parameter table in signatures/signDoc. The number of arrays included in
                the envelope_properties array SHALL equal the number of entries in the
                formats array. The values included in the array at position i of the
                envelope_properties array SHALL refer to the signature format value included
                at position i of the formats array. An empty array at the position i of the
                envelope_properties array indicates that the remote service supports the default signed
                envelope property for the signature format specified at the position i of the
                formats array, as defined in the Input parameter table in signatures/signDoc.
                """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        @JsonProperty("envelope_properties")
        List<List<String>> envelopeProperties
) {
}
