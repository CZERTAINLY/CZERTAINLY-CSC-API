package com.czertainly.csc.clients.ejbca;

import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.Success;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.providers.sanitization.DnAndSanSanitizer;
import com.czertainly.csc.providers.sanitization.EjbcaDnAndSanAndSanSanitizer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EjbcaDnAndSanSanitizerTest {

    DnAndSanSanitizer sanitizer = new EjbcaDnAndSanAndSanSanitizer();

    @Test
    void testEscapeBackslash() {
        assertEquals("Foo\\\\Bar", sanitizer.escapeValue("Foo\\Bar"));
    }

    @Test
    void testEscapeComma() {
        assertEquals("Foo\\, Inc", sanitizer.escapeValue("Foo, Inc"));
    }

    @Test
    void testEscapePlus() {
        assertEquals("user\\+admin", sanitizer.escapeValue("user+admin"));
    }

    @Test
    void testEscapeEquals() {
        assertEquals("name\\=value", sanitizer.escapeValue("name=value"));
    }

    @Test
    void testEscapeQuotes() {
        assertEquals("Foo\\\"Bar", sanitizer.escapeValue("Foo\"Bar"));
    }

    @Test
    void testEscapeHashAtStart() {
        assertEquals("\\#test", sanitizer.escapeValue("#test"));
    }

    @Test
    void testHashNotAtStart() {
        assertEquals("test#123", sanitizer.escapeValue("test#123"));
    }

    @Test
    void testMultipleSpecialChars() {
        assertEquals("Foo\\, Inc\\+Test\\=123", sanitizer.escapeValue("Foo, Inc+Test=123"));
    }

    @Test
    void testNoSpecialChars() {
        assertEquals("FooBar", sanitizer.escapeValue("FooBar"));
    }

    @Test
    void testEmptyValue() {
        assertEquals("", sanitizer.escapeValue(""));
    }

    @Test
    void testNullValue() {
        assertThrows(IllegalArgumentException.class, () -> sanitizer.escapeValue(null));
    }

    @Test
    void testComplexEscaping() {
        // Backslash must be escaped first, then other characters
        assertEquals("Foo\\\\\\,Bar", sanitizer.escapeValue("Foo\\,Bar"));
    }
}
