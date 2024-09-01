package com.czertainly.csc.components;

import org.springframework.stereotype.Component;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

@Component
public class DateConverter {

    private final DateTimeFormatter generalizedTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'");

    public String toGeneralizedTimeString(ZonedDateTime date) {
        return generalizedTimeFormatter.format(date);
    }

    public ZonedDateTime dateToZonedDateTime(Date date, ZoneId zoneId) {
        return date.toInstant()
                   .atZone(zoneId);
    }

}
