package com.czertainly.signserver.csc.common;

public record ErrorWithDescription(String error, String description) implements ErrorValue {
}
