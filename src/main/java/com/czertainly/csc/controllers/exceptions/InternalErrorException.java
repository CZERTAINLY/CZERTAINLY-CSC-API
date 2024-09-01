package com.czertainly.csc.controllers.exceptions;

public class InternalErrorException extends RuntimeException {


    public InternalErrorException(String errorDescription) {
        super(errorDescription);
    }
}
