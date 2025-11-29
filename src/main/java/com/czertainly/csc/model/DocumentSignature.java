package com.czertainly.csc.model;

import com.czertainly.csc.signing.configuration.SignaturePackaging;

import java.util.Arrays;
import java.util.Objects;
import java.util.StringJoiner;

public record DocumentSignature(
        byte[] value,
        SignaturePackaging packaging
) implements Signature {

    public static DocumentSignature of(byte[] value, SignaturePackaging packaging) {
        return new DocumentSignature(value, packaging);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;

        DocumentSignature that = (DocumentSignature) o;
        return Arrays.equals(value, that.value) && packaging == that.packaging;
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(value);
        result = 31 * result + Objects.hashCode(packaging);
        return result;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", DocumentSignature.class.getSimpleName() + "[", "]")
                .add("value=" + Arrays.toString(value))
                .add("packaging=" + packaging)
                .toString();
    }
}
