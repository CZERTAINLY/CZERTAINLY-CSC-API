package com.czertainly.csc.model;

import java.util.ArrayList;
import java.util.List;

public record Signatures<S extends Signature>(
        List<S> signatures
) implements SignaturesContainer<S> {

    public static <T extends Signature> Signatures<T> empty() {
        return new Signatures<>(new ArrayList<>());
    }

    public static <T extends Signature> Signatures<T> of(T signature) {
        return new Signatures<>(List.of(signature));
    }

    public static <T extends Signature> Signatures<T> of(List<T> signatures) {
        return new Signatures<>(signatures);
    }

    @Override
    public void extend(SignaturesContainer<S> sigs) {
        signatures.addAll(sigs.signatures());
    }
}