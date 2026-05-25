package com.otilm.csc.common.errorhandling;

import com.otilm.csc.common.result.TextError;

public class ErrorResultRetryException extends RuntimeException {

    private final TextError error;

    public ErrorResultRetryException(TextError error) {
        this.error = error;
    }

    public TextError getError() {
        return error;
    }


}
