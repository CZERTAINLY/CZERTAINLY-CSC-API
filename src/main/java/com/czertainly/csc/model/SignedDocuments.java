package com.czertainly.csc.model;

import com.czertainly.csc.signing.Signature;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public record SignedDocuments(
    List<Signature> signatures,
    Set<String> crls,
    Set<String> ocsps,
    Set<String> certs
) {

    public static SignedDocuments empty() {
        return new SignedDocuments(new ArrayList<>(), new HashSet<>(), new HashSet<>(), new HashSet<>());
    }

    public static SignedDocuments of(Signature signature) {
        return new SignedDocuments(List.of(signature), Set.of(), Set.of(), Set.of());
    }

    public static SignedDocuments of(List<Signature> signatures) {
        return new SignedDocuments(signatures, Set.of(), Set.of(), Set.of());
    }

    public void extend(SignedDocuments documents) {
        signatures.addAll(documents.signatures());
        crls.addAll(documents.crls());
        ocsps.addAll(documents.ocsps());
        certs.addAll(documents.certs());
    }
}