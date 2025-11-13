package com.czertainly.csc.model;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public record Signatures<S extends Signature>(
    List<S> signatures
) implements SignaturesContainer<S>{

    public static <T extends Signature> Signatures<T> empty() {
        return new Signatures<>(new ArrayList<>());
    }

    public static <T extends Signature> Signatures<T> of(T signature) {
        return new Signatures<>(List.of(signature));
    }

    public static <T extends Signature> Signatures<T> of(List<T> signatures) {
        return new Signatures<>(signatures);
    }

    public void extend(Signatures<S> sigs) {
        signatures.addAll(sigs.signatures());
    }

    @Override
    public void extend(SignaturesContainer<S> sigs) {
        signatures.addAll(sigs.signatures());
    }
}