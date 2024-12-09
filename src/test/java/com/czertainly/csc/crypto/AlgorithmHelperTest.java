package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static org.junit.jupiter.api.Assertions.*;

class AlgorithmHelperTest {

    private AlgorithmHelper algorithmHelper = new AlgorithmHelper();

    @Test
    void isSignatureAlgorithmReturnsTrueIfOidIsValidSignatureAlgorithm() {
        // given
        String oid = "1.2.840.10045.4.3.2";  // ECDSA with SHA256

        // when
        boolean isValid = algorithmHelper.isSignatureAlgorithm(oid);

        // then
        assertTrue(isValid);
    }

    @Test
    void isSignatureAlgorithmReturnsFalseIfOidIsNotValidSignatureAlgorithm() {
        // given
        String oid = "foo";

        // when
        boolean isValid = algorithmHelper.isSignatureAlgorithm(oid);

        // then
        assertFalse(isValid);
    }

    @Test
    void isSignatureAlgorithmThrowsNPEIfOidIsNull() {
        // given
        String oid = null;

        // when
        Executable cb = () -> algorithmHelper.isSignatureAlgorithm(oid);

        // then
        assertThrows(NullPointerException.class, cb);
    }

    @Test
    void isKeyAlgorithmReturnsTrueIfOidIsValidKeyAlgorithm() {
        // given
        String oid = "1.2.840.113549.1.1.1";  // RSA

        // when
        boolean isValid = algorithmHelper.isKeyAlgorithm(oid);

        // then
        assertTrue(isValid);
    }

    @Test
    void isKeyAlgorithmReturnsFalseIfOidIsNotValidKeyAlgorithm() {
        // given
        String oid = "foo";

        // when
        boolean isValid = algorithmHelper.isKeyAlgorithm(oid);

        assertFalse(isValid);
    }

    @Test
    void isKeyAlgorithmThrowsNPEIfOidIsNull() {
        // given
        String oid = null;

        // when
        Executable cb = () -> algorithmHelper.isKeyAlgorithm(oid);

        // then
        assertThrows(NullPointerException.class, cb);
    }

    @Test
    void isDigestAlgorithmReturnsTrueIfOidIsValidDigestAlgorithm() {
        // given
        String oid = "2.16.840.1.101.3.4.2.1"; // SHA-256

        // when
        boolean isValid = algorithmHelper.isDigestAlgorithm(oid);

        // then
        assertTrue(isValid);
    }

    @Test
    void isDigestAlgorithmReturnsFalseIfOidIsNotValidDigestAlgorithm() {
        // given
        String oid = "foo";

        // when
        boolean isValid = algorithmHelper.isDigestAlgorithm(oid);

        // then
        assertFalse(isValid);
    }

    @Test
    void isDigestAlgorithmThrowsNPEIfOidIsNull() {
        // given
        String oid = null;

        // when
        Executable cb = () -> algorithmHelper.isDigestAlgorithm(oid);

        // then
        assertThrows(NullPointerException.class, cb);
    }

    @Test
    void getSignatureAlgorithmNameReturnsValidName() {
        // given
        String oid = "1.2.840.10045.4.3.2";  // ECDSA with SHA256

        // when
        String result = algorithmHelper.getSignatureAlgorithmName(oid);

        // then
        assertEquals("SHA256WITHECDSA", result);
    }

    @Test
    void getSignatureAlgorithmNameReturnsNullForInvalidName() {
        // given
        String oid = "foo";

        // when
        String result = algorithmHelper.getSignatureAlgorithmName(oid);

        // then
        assertNull(result);
    }

    @Test
    void getSignatureAlgorithmNameThrowsNPEIfOidIsNull() {
        // given
        String oid = null;

        // when
        Executable cb = () -> algorithmHelper.getSignatureAlgorithmName(oid);

        // then
        assertThrows(NullPointerException.class, cb);
    }

    @Test
    void getDigestAlgorithmNameReturnsValidName() {
        // given
        String oid = "1.2.840.10045.4.3.2";

        // when
        String result = algorithmHelper.getDigestAlgorithmName(oid);

        // then
        assertEquals("SHA256WITHECDSA", result);
    }

    @Test
    void getDigestAlgorithmNameReturnsNullForInvalidName() {
        // given
        String oid = "foo";

        // when
        String result = algorithmHelper.getDigestAlgorithmName(oid);

        // then
        assertNull(result);
    }

    @Test
    void getDigestAlgorithmNameThrowsNPEIfOidIsNull() {
        // given
        String oid = null;

        // when
        Executable cb = () -> algorithmHelper.getDigestAlgorithmName(oid);

        // then
        assertThrows(NullPointerException.class, cb);
    }

    @Test
    void getAlgorithmNameReturnsValidName() {
        // given
        String oid = "1.2.840.10045.4.3.2";

        // when
        String result = algorithmHelper.getAlgorithmName(oid);

        // then
        assertEquals("SHA256WITHECDSA", result);
    }

    @Test
    void getAlgorithmNameReturnsNullForInvalidName() {
        // given
        String oid = "foo";

        // when
        String result = algorithmHelper.getAlgorithmName(oid);

        // then
        assertNull(result);
    }

    @Test
    void getAlgorithmNameThrowsNPEIfOidIsNull() {
        // given
        String oid = null;

        // when
        Executable cb = () -> algorithmHelper.getAlgorithmName(oid);

        // then
        assertThrows(NullPointerException.class, cb);
    }

    @Test
    void getKeyAlgorithmIdentifierReturnsValidIdentifier() {
        // given
        String name = "SHA256WITHECDSA";

        // when
        ASN1ObjectIdentifier result = algorithmHelper.getKeyAlgorithmIdentifier(name);

        // then
        assertEquals("1.2.840.10045.4.3.2", result.getId());
    }

    @Test
    void getKeyAlgorithmIdentifierReturnsNullForInvalidIdentifier() {
        // given
        String name = "foo";

        // when
        ASN1ObjectIdentifier result = algorithmHelper.getKeyAlgorithmIdentifier(name);

        // then
        assertNull(result);
    }

    @Test
    void getKeyAlgorithmIdentifierReturnNullForNullIdentifier() {
        // given
        String name = null;

        // when
        ASN1ObjectIdentifier result = algorithmHelper.getKeyAlgorithmIdentifier(name);

        // then
        assertNull(result);
    }

    @Test
    void isDigestAlgorithmCompatibleWithSignatureAlgorithmReturnsTrueForValidAlgorithms() {
        // given
        var digestAlgorithm = "2.16.840.1.101.3.4.2.1"; // SHA-256
        var signatureAlgorithm = "1.2.840.10045.4.3.2"; // ECDSA with SHA256

        // when
        boolean result = algorithmHelper.isDigestAlgorithmCompatibleWithSignatureAlgorithm(digestAlgorithm, signatureAlgorithm);

        // then
        assertTrue(result);
    }

    @Test
    void isDigestAlgorithmCompatibleWithSignatureAlgorithmReturnsFalseForInvalidAlgorithms() {
        // given
        var digestAlgorithm = "1.2.840.113549.2.5"; // MD5
        var signatureAlgorithm = "1.2.840.10045.4.3.2"; // ECDSA with SHA256

        // when
        boolean result = algorithmHelper.isDigestAlgorithmCompatibleWithSignatureAlgorithm(digestAlgorithm, signatureAlgorithm);

        // then
        assertFalse(result);
    }
}
