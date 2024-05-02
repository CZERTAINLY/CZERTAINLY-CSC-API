package com.czertainly.signserver.csc.common.exceptions;

public class InputDataException extends ApplicationException {

    public InputDataException(String message) {
        super(message);
    }

    public InputDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
