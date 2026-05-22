package com.czertainly.csc.api;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.annotation.JsonDeserialize;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class FlexibleStringDeserializerTest {

    private ObjectMapper objectMapper;

    record Wrapper(@JsonDeserialize(using = FlexibleStringDeserializer.class) String value) {}

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
    }

    @Test
    void deserializesPlainString() {
        Wrapper result = objectMapper.readValue("{\"value\":\"hello\"}", Wrapper.class);
        assertEquals("hello", result.value());
    }

    @Test
    void deserializesJsonObjectAsString() {
        Wrapper result = objectMapper.readValue("{\"value\":{\"key\":\"val\"}}", Wrapper.class);
        assertEquals("{\"key\":\"val\"}", result.value());
    }

    @Test
    void deserializesJsonArrayAsString() {
        Wrapper result = objectMapper.readValue("{\"value\":[1,2,3]}", Wrapper.class);
        assertEquals("[1,2,3]", result.value());
    }

    @Test
    void deserializesNullAsNull() {
        Wrapper result = objectMapper.readValue("{\"value\":null}", Wrapper.class);
        assertNull(result.value());
    }

    @Test
    void deserializesNumberAsString() {
        Wrapper result = objectMapper.readValue("{\"value\":42}", Wrapper.class);
        assertEquals("42", result.value());
    }
}
