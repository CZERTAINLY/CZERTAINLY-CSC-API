package com.czertainly.csc.controllers.exceptions;

public class ServerErrorException extends RuntimeException {

    String error;
    String errorDescription;

    public ServerErrorException(String error, String errorDescription) {
        super(error + ": " + errorDescription);
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public ServerErrorException(String error, String errorDescription, Throwable cause) {
        super(error + ": " + errorDescription, cause);
        this.error = error;
        this.errorDescription = errorDescription;
    }


    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }
}
