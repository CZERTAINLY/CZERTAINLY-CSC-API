package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;

import java.util.Map;

public class CustomAlgorithmNameFinder extends DefaultAlgorithmNameFinder {

    public ASN1ObjectIdentifier getKeyAlgorithmIdentifier(String algorithmName) {
        for (Map.Entry<ASN1ObjectIdentifier, String> entry : getAlgorithmsMap().entrySet()) {
            if (entry.getValue().equals(algorithmName)) {
                return entry.getKey();
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Map<ASN1ObjectIdentifier, String> getAlgorithmsMap() {
        try {
            java.lang.reflect.Field field = DefaultAlgorithmNameFinder.class.getDeclaredField("algorithms");
            field.setAccessible(true);
            return (Map<ASN1ObjectIdentifier, String>) field.get(this);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException("Unable to access algorithms map", e);
        }
    }
}
