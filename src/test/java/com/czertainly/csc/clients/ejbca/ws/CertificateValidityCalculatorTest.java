package com.czertainly.csc.clients.ejbca.ws;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.ZonedDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificateValidityCalculatorTest {

    CertificateValidityCalculator calculator = new CertificateValidityCalculator();

    @Test
    void calculatesValidityStartWithPositiveOffset() {
        // given
        var now = ZonedDateTime.now();
        var offset = Duration.ofDays(1);

        // when
        var result = calculator.calculateValidityStart(now, offset);

        // then
        assertEquals(now.plusDays(1), result);
    }

    @Test
    void calculatesValidityStartWithNegativeOffset() {
        // given
        var now = ZonedDateTime.now();
        var offset = Duration.ofDays(-1);

        // when
        var result = calculator.calculateValidityStart(now, offset);

        // then
        assertEquals(now.minusDays(1), result);
    }
}
