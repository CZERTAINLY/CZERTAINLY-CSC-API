package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class CustomAlgorithmNameFinderTest {

    private CustomAlgorithmNameFinder finder = new CustomAlgorithmNameFinder();

    @Test
    void getKeyAlgorithmIdentifierReturnsValidIdentifier() {
        // given
        String name = "SHA256WITHECDSA";

        // when
        ASN1ObjectIdentifier result = finder.getKeyAlgorithmIdentifier(name);

        // then
        assertEquals("1.2.840.10045.4.3.2", result.getId());
    }

    @Test
    void getKeyAlgorithmIdentifierReturnsNullForInvalidIdentifier() {
        // given
        String name = "foo";

        // when
        ASN1ObjectIdentifier result = finder.getKeyAlgorithmIdentifier(name);

        // then
        assertNull(result);
    }

    @Test
    void getKeyAlgorithmIdentifierReturnNullForNullIdentifier() {
        // given
        String name = null;

        // when
        ASN1ObjectIdentifier result = finder.getKeyAlgorithmIdentifier(name);

        // then
        assertNull(result);
    }
}