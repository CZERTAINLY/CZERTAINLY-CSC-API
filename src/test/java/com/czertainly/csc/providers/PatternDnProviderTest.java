package com.czertainly.csc.providers;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.providers.sanitization.DnAndSanSanitizer;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.czertainly.csc.utils.assertions.ResultAssertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PatternDnProviderTest {

    @Test
    void testBasicPatternReplacement() {
        //given
        PatternDnProvider provider = new PatternDnProvider("CN=$[cn]", List.of("CN"), null);

        //when
        Result<String, TextError> result = provider.getDistinguishedName(() -> Map.of("cn", "John"));

        //then
        assertEquals("CN=John", assertSuccessAndGet(result));
    }

    @Test
    void testMultipleComponentsReplacement() {
        //given
        PatternDnProvider provider = new PatternDnProvider(
            "CN=$[cn],O=$[org],C=$[country]",
            List.of("CN", "O", "C"), null
        );

        //when
        Result<String, TextError> result = provider.getDistinguishedName(() -> Map.of(
            "cn", "John Doe",
            "org", "Example Corp",
            "country", "US"
        ));

        //then
        assertEquals("CN=John Doe, O=Example Corp, C=US", assertSuccessAndGet(result));
    }

    @Test
    void testSanitizationApplied() {
        //given
        DnAndSanSanitizer sanitizer = value -> {
            return value.replace(",", "\\,");
        };
        PatternDnProvider provider = new PatternDnProvider(
            "CN=$[cn]",
            List.of("CN"),
            sanitizer
        );

        //when
        Result<String, TextError> result = provider.getDistinguishedName(() -> Map.of("cn", "Foo, Inc"));

        //then
        assertEquals("CN=Foo\\, Inc", assertSuccessAndGet(result));
    }

    @Test
    void testSanitizationWithMultipleComponents() {
        //given
        DnAndSanSanitizer sanitizer = new DnAndSanSanitizer() {
            @Override
            public String escapeValue(String value) {
                return value.replace("+", "\\+").replace(",", "\\,");
            }
        };
        PatternDnProvider provider = new PatternDnProvider(
            "CN=$[cn],O=$[org]",
            List.of("CN", "O"),
            sanitizer
        );

        //when
        Result<String, TextError> result = provider.getDistinguishedName(() -> Map.of(
            "cn", "Test+User",
            "org", "Foo, Inc"
        ));

        //then
        assertEquals("CN=Test\\+User, O=Foo\\, Inc", assertSuccessAndGet(result));
    }
}
