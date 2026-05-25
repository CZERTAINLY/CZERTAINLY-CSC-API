package com.otilm.csc.controllers.exceptions;

public class BadRequestException extends RuntimeException {

    public BadRequestException(String errorDescription) {
        super(errorDescription);
    }
}
