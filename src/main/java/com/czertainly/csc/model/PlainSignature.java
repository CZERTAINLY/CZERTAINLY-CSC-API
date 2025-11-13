package com.czertainly.csc.model;

public record PlainSignature(
        byte[] value
) implements Signature {

    public static PlainSignature of(byte[] value) {
        return new PlainSignature(value);
    }
}
