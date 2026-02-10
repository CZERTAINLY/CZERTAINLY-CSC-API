package com.czertainly.csc.providers;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.providers.sanitization.DnAndSanSanitizer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static com.czertainly.csc.utils.assertions.ResultAssertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class PatternSanProviderTest {

    @Test
    void shouldReplaceSinglePlaceholder() {
        // GIVEN
        PatternSanProvider provider = new PatternSanProvider("rfc822Name=$[email]", List.of("rfc822Name"), null);

        // WHEN
        Result<String, TextError> result = provider.getSan(() -> Map.of("email", "john@example.com"));

        // THEN
        assertEquals("rfc822Name=john@example.com", assertSuccessAndGet(result));
    }

    @Test
    void shouldReplaceMultiplePlaceholders() {
        // GIVEN
        PatternSanProvider provider = new PatternSanProvider(
            "rfc822Name=$[email],dNSName=$[dns]",
            List.of("rfc822Name", "dNSName"), null
        );

        // WHEN
        Result<String, TextError> result = provider.getSan(() -> Map.of(
            "email", "john@example.com",
            "dns", "example.com"
        ));

        // THEN
        assertEquals("rfc822Name=john@example.com, dNSName=example.com", assertSuccessAndGet(result));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "None", "none", "NONE", "null", "NULL"})
    void shouldReturnNullWhenPatternIsEmpty(String pattern) {
        // GIVEN
        PatternSanProvider provider = new PatternSanProvider(pattern, List.of(), null);

        // WHEN
        Result<String, TextError> result = provider.getSan(() -> Map.of("email", "john@example.com"));

        // THEN
        assertNull(assertSuccessAndGet(result));
    }

    @Test
    void shouldApplySanitization() {
        // GIVEN
        DnAndSanSanitizer sanitizer = value -> value.replace(",", "\\,");
        PatternSanProvider provider = new PatternSanProvider(
            "rfc822Name=$[email]",
            List.of("rfc822Name"),
            sanitizer
        );

        // WHEN
        Result<String, TextError> result = provider.getSan(() -> Map.of("email", "first,last@example.com"));

        // THEN
        assertEquals("rfc822Name=first\\,last@example.com", assertSuccessAndGet(result));
    }

    @Test
    void shouldApplySanitizationToMultipleComponents() {
        // GIVEN
        DnAndSanSanitizer sanitizer = value -> value.replace("+", "\\+").replace(",", "\\,");
        PatternSanProvider provider = new PatternSanProvider(
            "rfc822Name=$[email],dNSName=$[dns]",
            List.of("rfc822Name", "dNSName"),
            sanitizer
        );

        // WHEN
        Result<String, TextError> result = provider.getSan(() -> Map.of(
            "email", "user+tag@example.com",
            "dns", "a,b.example.com"
        ));

        // THEN
        assertEquals("rfc822Name=user\\+tag@example.com, dNSName=a\\,b.example.com", assertSuccessAndGet(result));
    }

    @Test
    void shouldReturnErrorWhenRequiredPlaceholderIsMissing() {
        // GIVEN
        PatternSanProvider provider = new PatternSanProvider(
            "rfc822Name=$[email]",
            List.of("rfc822Name"), null
        );

        // WHEN
        Result<String, TextError> result = provider.getSan(Map::of);

        // THEN
        assertError(result);
    }
}
