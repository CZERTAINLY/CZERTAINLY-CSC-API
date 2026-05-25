package com.otilm.csc.common.exceptions;

public class RemoteSystemException extends ApplicationException {

    public RemoteSystemException(String message) {
        super(message);
    }

    public RemoteSystemException(String message, Throwable cause) {
        super(message, cause);
    }
}
