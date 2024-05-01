package com.czertainly.signserver.csc.crypto;

import java.util.Map;

public class DigestAlgorithmJavaName {

    private static final Map<String, String> digestAlgoJavaNames = Map.of(
            "SHA1", "SHA-1",
            "SHA224", "SHA-224",
            "SHA256", "SHA-256",
            "SHA384", "SHA-384",
            "SHA512", "SHA-512"
    );


    public static String get(String digestAlgo) {
        return digestAlgoJavaNames.getOrDefault(digestAlgo, digestAlgo);
    }

}
