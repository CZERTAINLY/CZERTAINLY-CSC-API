package com.otilm.csc.controllers.exceptions;

public class ForbiddenException extends RuntimeException {

    public ForbiddenException(String error, String errorDescription) {
        super(error + ": " + errorDescription);
    }
}
