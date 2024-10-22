package com.czertainly.csc.clients.ejbca.ws;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.ZonedDateTime;

@Component
public class CertificateValidityCalculator {

    public ZonedDateTime calculateValidityStart(ZonedDateTime now, Duration offset) {
        long nanos = offset.toNanos();
        return now.plusNanos(nanos);
    }

    public ZonedDateTime calculateValidityEnd(ZonedDateTime start, Duration validity) {
        long nanosValidity = validity.toNanos();
        return start.plusNanos(nanosValidity);
    }
}
