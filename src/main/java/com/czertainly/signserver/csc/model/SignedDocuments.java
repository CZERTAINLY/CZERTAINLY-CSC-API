package com.czertainly.signserver.csc.model;

import com.czertainly.signserver.csc.signing.Signature;

import java.util.List;

public record SignedDocuments(
    List<Signature> signatures,
    List<String> crls,
    List<String> ocsps,
    List<String> certs
){
}
