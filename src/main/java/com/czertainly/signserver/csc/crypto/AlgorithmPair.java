package com.czertainly.signserver.csc.crypto;

import java.util.Map;

public record AlgorithmPair(String keyAlgo, String digestAlgo) {

    public String digestAlgoJavaName() {
        return digestAlgo.replace("-", "");
    }

}