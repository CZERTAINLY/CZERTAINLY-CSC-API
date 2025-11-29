package com.czertainly.csc.common.exceptions;

public class ApplicationConfigurationException extends ApplicationException {

    public ApplicationConfigurationException(String message) {
        super(message);
    }

    public ApplicationConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
