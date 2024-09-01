package com.czertainly.csc.common.result;

import java.util.function.Consumer;
import java.util.function.Function;

public sealed interface Result<V, E extends ErrorValue> permits Error, Success {
    static <V, E extends ErrorValue> Result<V, E> success(V value) {
        return new Success<>(value);
    }

    static <E extends ErrorValue> Result<Void, E> emptySuccess() {
        return new Success<>(null);
    }

    static <V, E extends ErrorValue> Result<V, E> error(E error) {
        return new Error<>(error);
    }

    <V2> Result<V2, E> repack();

    <U> Result<U, E> map(Function<V, U> mapper);

    <U> Result<U, E> flatMap(Function<V, Result<U, E>> mapper);

    <E2 extends ErrorValue> Result<V, E2> mapError(Function<E, E2> mapper);

    <E2 extends ErrorValue> Result<V, E2> flatMapError(Function<E, Result<V, E2>> mapper);

    Result<V, E> consume(Consumer<V> consumer);

    Result<V, E> consumeError(Consumer<E> consumer);

    Result<V, E> ifSuccess(Runnable runnable);

    Result<V, E> ifError(Runnable runnable);

    Result<V, E> validate(Function<V, Boolean> validator, E error);

    Result<V, E> validate(Function<V, Boolean> validator, Function<V,E> errorSupplier);

    Result<V,E> runIf(Function<V,Boolean> condition, Runnable runnable);

    Result<V,E> runIf(Function<V,Boolean> condition, Consumer<V> runnable);

    V unwrap();

    E unwrapError();
}
