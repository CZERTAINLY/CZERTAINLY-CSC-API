package com.otilm.csc.controllers.exceptions;

public class ServiceUnavailableException extends RuntimeException {

    public ServiceUnavailableException(String error, String errorDescription) {
        super(error + ": " + errorDescription);
    }
}
