package com.czertainly.csc.controllers.exceptions;

public class UnauthorizedException extends RuntimeException {

    public UnauthorizedException(String errorDescription) {
        super(errorDescription);
    }
}
