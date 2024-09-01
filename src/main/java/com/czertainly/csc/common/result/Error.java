package com.czertainly.csc.common.result;

import java.util.function.Consumer;
import java.util.function.Function;

public record Error<V, E extends ErrorValue>(E error) implements Result<V, E> {

    @Override
    public <V2> Result<V2, E> repack() {
        return Result.error(this.error);
    }

    @Override
    public <U> Result<U, E> map(Function<V, U> mapper) {
        return Result.error(error);
    }

    @Override
    public <U> Result<U, E> flatMap(Function<V, Result<U, E>> mapper) {
        return Result.error(error);
    }

    @Override
    public <E2 extends ErrorValue> Result<V, E2> mapError(Function<E, E2> mapper) {
        return Result.error(mapper.apply(error));
    }

    @Override
    public <E2 extends ErrorValue> Result<V, E2> flatMapError(Function<E, Result<V, E2>> mapper) {
        return mapper.apply(error);
    }

    @Override
    public Result<V, E> consume(Consumer<V> consumer) {
        return this;
    }

    @Override
    public Result<V, E> consumeError(Consumer<E> consumer) {
        consumer.accept(error);
        return this;
    }

    @Override
    public Result<V, E> ifSuccess(Runnable runnable) {
        return this;
    }

    @Override
    public Result<V, E> ifError(Runnable runnable) {
        runnable.run();
        return this;
    }

    @Override
    public Result<V, E> validate(Function<V, Boolean> validator, E error) {
        return this;
    }

    @Override
    public Result<V, E> validate(Function<V, Boolean> validator, Function<V, E> errorSupplier) {
        return this;
    }

    @Override
    public Result<V, E> runIf(Function<V, Boolean> condition, Runnable runnable) {
        return this;
    }

    @Override
    public Result<V, E> runIf(Function<V, Boolean> condition, Consumer<V> runnable) {
        return this;
    }

    @Override
    public V unwrap() {
        throw new UnsupportedOperationException("Cannot unwrap value from Error.");
    }

    @Override
    public E unwrapError() {
        return error;
    }

    public Result<V, E> $() {
        return Result.error(error);
    }
}
