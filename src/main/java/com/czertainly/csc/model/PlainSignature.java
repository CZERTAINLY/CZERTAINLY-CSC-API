package com.czertainly.csc.model;

import java.util.Arrays;
import java.util.StringJoiner;

public record PlainSignature(
        byte[] value
) implements Signature {

    public static PlainSignature of(byte[] value) {
        return new PlainSignature(value);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;

        PlainSignature that = (PlainSignature) o;
        return Arrays.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", PlainSignature.class.getSimpleName() + "[", "]")
                .add("value=" + Arrays.toString(value))
                .toString();
    }
}
