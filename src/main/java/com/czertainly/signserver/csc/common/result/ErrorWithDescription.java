package com.czertainly.signserver.csc.common.result;

public record ErrorWithDescription(String error, String description) implements ErrorValue {
}
