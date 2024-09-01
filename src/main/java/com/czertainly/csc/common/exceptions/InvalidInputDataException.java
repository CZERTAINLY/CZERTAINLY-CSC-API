package com.czertainly.csc.common.exceptions;

public class InvalidInputDataException extends ApplicationException {

    public InvalidInputDataException(String message) {
        super(message);
    }

    public static InvalidInputDataException of(String message) {
        return new InvalidInputDataException(message);
    }

    public static InvalidInputDataException of(String template, Object... args) {
        return new InvalidInputDataException(String.format(template, args));
    }

    public InvalidInputDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
