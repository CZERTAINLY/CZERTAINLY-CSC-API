package com.czertainly.csc.model;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public record SignaturesWithValidationInfo<S extends Signature>(
    List<S> signatures,
    Set<String> crls,
    Set<String> ocsps,
    Set<String> certs
) implements SignaturesContainer<S>{

    public static <T extends Signature> SignaturesWithValidationInfo<T> empty() {
        return new SignaturesWithValidationInfo<>(new ArrayList<>(), new HashSet<>(), new HashSet<>(), new HashSet<>());
    }

    public static <T extends Signature> SignaturesWithValidationInfo<T> of(T signature) {
        return new SignaturesWithValidationInfo<>(List.of(signature), Set.of(), Set.of(), Set.of());
    }

    public static <T extends Signature> SignaturesWithValidationInfo<T> of(List<T> signatures) {
        return new SignaturesWithValidationInfo<>(signatures, Set.of(), Set.of(), Set.of());
    }

    @Override
    public void extend(SignaturesContainer<S> sigs) {
        if (sigs instanceof SignaturesWithValidationInfo<S>(
                List<S> signatures1, Set<String> crls1, Set<String> ocsps1, Set<String> certs1
        )) {
            signatures.addAll(signatures1);
            crls.addAll(crls1);
            ocsps.addAll(ocsps1);
            certs.addAll(certs1);
        } else {
            throw new IllegalArgumentException(
                    "Cannot extend SignaturesWithValidationInfo with different SignaturesContainer type");
        }
    }
}