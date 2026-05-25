package com.otilm.csc.api;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

public class FlexibleStringDeserializer extends StdDeserializer<String> {

    public FlexibleStringDeserializer() {
        super(String.class);
    }

    @Override
    public String deserialize(JsonParser p, DeserializationContext ctx) throws JacksonException {
        if (p.currentToken() == JsonToken.START_OBJECT || p.currentToken() == JsonToken.START_ARRAY) {
            return ctx.readTree(p).toString();
        }
        return p.getString();
    }
}
