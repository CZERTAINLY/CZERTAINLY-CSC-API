package com.czertainly.csc.common.result;

import java.util.function.Consumer;
import java.util.function.Function;

public record Success<V, E extends ErrorValue>(V value) implements Result<V, E> {

    @Override
    public <V2> Result<V2, E> repack() {
        throw new UnsupportedOperationException("Success can't be repacked");
    }

    @Override
    public <U> Result<U, E> map(Function<V, U> mapper) {
        return Result.success(mapper.apply(value));
    }

    @Override
    public <U> Result<U,E > flatMap(Function<V, Result<U, E>> mapper) {
        return mapper.apply(value);
    }

    @Override
    public <E2 extends ErrorValue> Result<V, E2> mapError(Function<E, E2> mapper) {
        return Result.success(value);
    }

    @Override
    public <E2 extends ErrorValue> Result<V, E2> flatMapError(Function<E, Result<V, E2>> mapper) {
        return Result.success(value);
    }

    @Override
    public Result<V, E> consume(Consumer<V> consumer) {
        consumer.accept(value);
        return this;
    }

    @Override
    public Result<V, E> consumeError(Consumer<E> consumer) {
        return this;
    }

    @Override
    public Result<V, E> ifSuccess(Runnable runnable) {
        runnable.run();
        return this;
    }

    @Override
    public Result<V, E> ifError(Runnable runnable) {
        return this;
    }

    @Override
    public Result<V, E> validate(Function<V, Boolean> validator, E error) {
        return validator.apply(value) ? Result.error(error) : this;
    }

    @Override
    public Result<V, E> validate(Function<V, Boolean> validator, Function<V, E> errorSupplier) {
        return validator.apply(value) ? Result.error(errorSupplier.apply(value)) : this;
    }

    @Override
    public Result<V, E> runIf(Function<V, Boolean> condition, Runnable runnable) {
        if (condition.apply(value)) {
            runnable.run();
        }
        return this;
    }

    @Override
    public Result<V, E> runIf(Function<V, Boolean> condition, Consumer<V> runnable) {
        if (condition.apply(value)) {
            runnable.accept(value);
        }
        return this;
    }

    @Override
    public V unwrap() {
        return value;
    }

    @Override
    public E unwrapError() {
        throw new UnsupportedOperationException("Cannot unwrap error from Success");
    }
}
