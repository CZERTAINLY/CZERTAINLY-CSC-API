package com.czertainly.csc.common.result;

public class TextErrorWithRetryIndication extends TextError {

    private final Boolean shouldRetry;


    public TextErrorWithRetryIndication(String error, Boolean shouldRetry) {
        super(error);
        this.shouldRetry = shouldRetry;
    }

    public static TextErrorWithRetryIndication of(String error, Boolean shouldRetry) {
        return new TextErrorWithRetryIndication(error, shouldRetry);
    }

    public static TextErrorWithRetryIndication doRetry(String error) {
        return new TextErrorWithRetryIndication(error, true);
    }

    public static TextErrorWithRetryIndication doNotRetry(String error) {
        return new TextErrorWithRetryIndication(error, false);
    }

    public Boolean getShouldRetry() {
        return shouldRetry;
    }
}
