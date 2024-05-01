package com.czertainly.signserver.csc.api.auth.exceptions;

import com.czertainly.signserver.csc.common.exceptions.ApplicationException;

public class JwksDownloadException extends ApplicationException {

    public JwksDownloadException(String message) {
        super(message);
    }

    public JwksDownloadException(String message, Throwable cause) {
        super(message, cause);
    }
}
