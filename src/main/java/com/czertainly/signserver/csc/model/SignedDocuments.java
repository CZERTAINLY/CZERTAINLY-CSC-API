package com.czertainly.signserver.csc.model;

import com.czertainly.signserver.csc.signing.Signature;

import java.util.List;
import java.util.Set;

public record SignedDocuments(
    List<Signature> signatures,
    Set<String> crls,
    Set<String> ocsps,
    Set<String> certs
){
}
