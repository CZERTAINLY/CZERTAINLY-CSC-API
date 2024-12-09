package com.czertainly.csc.configuration.validations;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UrlValidatorTest {

    UrlValidator urlValidator = new UrlValidator();

    @Test
    void isValidReturnsTrueForValidUrl() {
        // given
        String url = "http://www.google.com";

        // when
        boolean isValid = urlValidator.isValid(url, null);

        // then
        assertTrue(isValid);
    }

    @Test
    void isValidReturnsFalseForInvalidUrl() {
        // given
        String url = "not-a-valid-url";

        // when
        boolean isValid = urlValidator.isValid(url, null);

        // then
        assertFalse(isValid);
    }

    @Test
    void isValidReturnsFalseForNullUrl() {
        // given
        String url = null;

        // when
        boolean isValid = urlValidator.isValid(url, null);

        // then
        assertFalse(isValid);
    }
}