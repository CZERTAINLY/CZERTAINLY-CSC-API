package com.czertainly.signserver.csc.common.result;

import java.util.function.Consumer;
import java.util.function.Function;

public class Result <TValue, TError extends ErrorValue> {

    private final TValue value;
    private final TError error;
    private final boolean isOk;

    public static <T, E extends ErrorValue> Result<T, E> ok(T result) {
        return new Result<>(result);
    }

    public static <T, E extends ErrorValue> Result<T, E> error(E error) {
        return new Result<>(error);
    }

    private Result(TValue value) {
        this.value = value;
        this.error = null;
        this.isOk = true;
    }

    private Result(TError error) {
        this.error = error;
        this.value = null;
        this.isOk = false;
    }

    public <U, E extends Throwable> U with(Function<TValue, U> okConsumer, Function<TError, U> errorConsumer) throws E {
        if (isOk) {
            return okConsumer.apply(value);
        } else {
            return errorConsumer.apply(error);
        }
    }

    public <E extends Throwable> void doWith(Consumer<TValue> okConsumer, Consumer<TError> errorConsumer) throws E {
        if (isOk) {
            okConsumer.accept(value);
        } else {
            errorConsumer.accept(error);
        }
    }

    public void withValue(Function<TValue, Void> okConsumer) {
        if (isOk) {
            okConsumer.apply(value);
        }
    }

    public void withError(Function<TError, Void> errorConsumer) {
        if (!isOk) {
            errorConsumer.apply(error);
        }
    }

    public TValue getValue() {
        return value;
    }

    public TError getError() {
        return error;
    }

    public boolean isSuccess() {
        return isOk;
    }

    public boolean isError() {
        return !isOk;
    }

}