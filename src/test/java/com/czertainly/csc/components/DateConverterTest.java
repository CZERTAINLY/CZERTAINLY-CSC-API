package com.czertainly.csc.components;

import org.junit.jupiter.api.Test;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DateConverterTest {

    private final DateConverter dateConverter = new DateConverter();

    @Test
    void toGeneralizedTimeString() {
        // given
        ZonedDateTime dateTime = ZonedDateTime.parse("2024-11-21T14:00:00Z");

        // when
        String result = dateConverter.toGeneralizedTimeString(dateTime);

        // then
        assertEquals("20241121140000Z", result);
    }

    @Test
    void dateToZonedDateTime() {
        // given
        Date date = new Date(1732194916000L); // 2024-11-21T13:15:16:000
        ZoneId zoneId = ZoneId.of("Z");

        // when
        ZonedDateTime result = dateConverter.dateToZonedDateTime(date, zoneId);

        // then
        assertEquals(2024, result.getYear());
        assertEquals(11, result.getMonthValue());
        assertEquals(21, result.getDayOfMonth());
        assertEquals(13, result.getHour());
        assertEquals(15, result.getMinute());
        assertEquals(16, result.getSecond());
        assertEquals(0, result.getNano());
        assertEquals(zoneId, result.getZone());
    }
}
