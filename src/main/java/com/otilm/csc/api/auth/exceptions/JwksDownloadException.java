package com.otilm.csc.api.auth.exceptions;

import com.otilm.csc.common.exceptions.ApplicationException;

public class JwksDownloadException extends ApplicationException {

    public JwksDownloadException(String message) {
        super(message);
    }

    public JwksDownloadException(String message, Throwable cause) {
        super(message, cause);
    }
}
