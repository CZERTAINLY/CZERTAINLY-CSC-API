package com.czertainly.signserver.csc.api.signdoc;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AttributeDto(
        @JsonProperty("attribute_name")
        String name,

        @JsonProperty("attribute_value")
        String value
) {
}
