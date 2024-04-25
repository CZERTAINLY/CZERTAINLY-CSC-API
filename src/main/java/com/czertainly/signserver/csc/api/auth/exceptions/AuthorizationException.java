package com.czertainly.signserver.csc.api.auth.exceptions;

import com.czertainly.signserver.csc.common.ApplicationException;

public class AuthorizationException extends ApplicationException {
    public AuthorizationException(String message) {
        super(message);
    }

    public AuthorizationException(String message, Throwable cause) {
        super(message, cause);
    }
}
