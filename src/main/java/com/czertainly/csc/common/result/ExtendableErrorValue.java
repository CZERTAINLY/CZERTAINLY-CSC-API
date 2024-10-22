package com.czertainly.csc.common.result;

public abstract class ExtendableErrorValue<T> implements ErrorValue {
    private final ExtendableErrorValue<T> extended;
    private final String error;

    public ExtendableErrorValue(String error) {
        this.extended = null;
        this.error = error;
    }

    public ExtendableErrorValue(String error, ExtendableErrorValue<T> originalError) {
        this.extended = originalError;
        this.error = error;
    }

    public String getErrorText() {
        return toString();
    }

    public abstract ExtendableErrorValue<T> extend(T error);

    public String toString() {
        if (this.extended == null) {
            return error;
        } else {
            return String.format("%s: %s", error, extended);
        }
    }
}
