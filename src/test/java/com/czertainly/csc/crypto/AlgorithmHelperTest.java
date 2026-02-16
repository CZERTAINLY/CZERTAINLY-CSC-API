package com.czertainly.csc.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AlgorithmHelperTest {

    private final AlgorithmHelper algorithmHelper = new AlgorithmHelper();

    private static final ASN1ObjectIdentifier UNKNOWN_OID = new ASN1ObjectIdentifier("1.2.3.4.5.6.7");

    // --- getFamily tests ---

    @Test
    void getFamilyReturnsKeyForRsa() {
        // GIVEN
        var oid = PKCSObjectIdentifiers.rsaEncryption;

        // WHEN
        var result = algorithmHelper.getFamily(oid);

        // THEN
        assertEquals(AlgorithmFamily.RSAES_PKCS1, result);
    }

    @Test
    void getFamilyReturnsRsaForSha256WithRsa() {
        // GIVEN
        var oid = PKCSObjectIdentifiers.sha256WithRSAEncryption;

        // WHEN
        var result = algorithmHelper.getFamily(oid);

        // THEN
        assertEquals(AlgorithmFamily.RSASSA_PKCS1, result);
    }

    @Test
    void getFamilyReturnsEcdsaForSha256WithEcdsa() {
        // GIVEN
        var oid = X9ObjectIdentifiers.ecdsa_with_SHA256;

        // WHEN
        var result = algorithmHelper.getFamily(oid);

        // THEN
        assertEquals(AlgorithmFamily.ECDSA, result);
    }

    @Test
    void getFamilyReturnsPssForRsassaPss() {
        // GIVEN
        var oid = PKCSObjectIdentifiers.id_RSASSA_PSS;

        // WHEN
        var result = algorithmHelper.getFamily(oid);

        // THEN
        assertEquals(AlgorithmFamily.RSASSA_PSS, result);
    }

    @Test
    void getFamilyReturnsPureForEd25519() {
        // GIVEN
        var oid = EdECObjectIdentifiers.id_Ed25519;

        // WHEN
        var result = algorithmHelper.getFamily(oid);

        // THEN
        assertEquals(AlgorithmFamily.EdDSA, result);
    }

    @Test
    void getFamilyReturnsPureForEd448() {
        // GIVEN
        var oid = EdECObjectIdentifiers.id_Ed448;

        // WHEN
        var result = algorithmHelper.getFamily(oid);

        // THEN
        assertEquals(AlgorithmFamily.EdDSA, result);
    }

    @Test
    void getFamilyReturnsNullForUnknownOid() {
        // WHEN
        var result = algorithmHelper.getFamily(UNKNOWN_OID);

        // THEN
        assertNull(result);
    }

    // --- isKeyAlgorithm tests ---

    @Test
    void isKeyAlgorithmReturnsTrueForValidKeyAlgorithm() {
        // GIVEN
        var oid = PKCSObjectIdentifiers.rsaEncryption;

        // WHEN
        var result = algorithmHelper.isKeyAlgorithm(oid);

        // THEN
        assertTrue(result);
    }

    @Test
    void isKeyAlgorithmReturnsFalseForUnknownOid() {
        // WHEN
        var result = algorithmHelper.isKeyAlgorithm(UNKNOWN_OID);

        // THEN
        assertFalse(result);
    }

    @Test
    void isKeyAlgorithmReturnsFalseForNull() {
        // WHEN
        var result = algorithmHelper.isKeyAlgorithm(null);

        // THEN
        assertFalse(result);
    }

    // --- isDigestAlgorithm tests ---

    @Test
    void isDigestAlgorithmReturnsTrueForValidDigestAlgorithm() {
        // GIVEN
        var oid = NISTObjectIdentifiers.id_sha256;

        // WHEN
        var result = algorithmHelper.isDigestAlgorithm(oid);

        // THEN
        assertTrue(result);
    }

    @Test
    void isDigestAlgorithmReturnsFalseForNonDigestAlgorithm() {
        // GIVEN
        var oid = PKCSObjectIdentifiers.rsaEncryption;

        // WHEN
        var result = algorithmHelper.isDigestAlgorithm(oid);

        // THEN
        assertFalse(result);
    }

    @Test
    void isDigestAlgorithmThrowsNPEForNull() {
        // WHEN / THEN
        assertThrows(NullPointerException.class, () -> algorithmHelper.isDigestAlgorithm(null));
    }

    // --- getSignatureAlgorithmName tests ---

    @Test
    void getSignatureAlgorithmNameReturnsNameForKnownOid() {
        // GIVEN
        var oid = X9ObjectIdentifiers.ecdsa_with_SHA256;

        // WHEN
        var result = algorithmHelper.getSignatureAlgorithmName(oid);

        // THEN
        assertEquals("SHA256WITHECDSA", result);
    }

    @Test
    void getSignatureAlgorithmNameReturnsOidStringForUnknownOid() {
        // WHEN
        var result = algorithmHelper.getSignatureAlgorithmName(UNKNOWN_OID);

        // THEN
        assertEquals("1.2.3.4.5.6.7", result);
    }

    @Test
    void getSignatureAlgorithmNameThrowsNPEForNull() {
        // WHEN / THEN
        assertThrows(NullPointerException.class, () -> algorithmHelper.getSignatureAlgorithmName(null));
    }

    // --- getDigestAlgorithmName tests ---

    @Test
    void getDigestAlgorithmNameReturnsNameForKnownOid() {
        // GIVEN
        var oid = X9ObjectIdentifiers.ecdsa_with_SHA256;

        // WHEN
        var result = algorithmHelper.getDigestAlgorithmName(oid);

        // THEN
        assertEquals("SHA256WITHECDSA", result);
    }

    @Test
    void getDigestAlgorithmNameReturnsOidStringForUnknownOid() {
        // WHEN
        var result = algorithmHelper.getDigestAlgorithmName(UNKNOWN_OID);

        // THEN
        assertEquals("1.2.3.4.5.6.7", result);
    }

    @Test
    void getDigestAlgorithmNameThrowsNPEForNull() {
        // WHEN / THEN
        assertThrows(NullPointerException.class,
                () -> algorithmHelper.getDigestAlgorithmName((ASN1ObjectIdentifier) null));
    }

    // --- getAlgorithmName tests ---

    @Test
    void getAlgorithmNameReturnsNameForKnownOid() {
        // GIVEN
        var oid = X9ObjectIdentifiers.ecdsa_with_SHA256;

        // WHEN
        var result = algorithmHelper.getAlgorithmName(oid);

        // THEN
        assertEquals("SHA256WITHECDSA", result);
    }

    @Test
    void getAlgorithmNameReturnsOidStringForUnknownOid() {
        // WHEN
        var result = algorithmHelper.getAlgorithmName(UNKNOWN_OID);

        // THEN
        assertEquals("1.2.3.4.5.6.7", result);
    }

    @Test
    void getAlgorithmNameThrowsNPEForNull() {
        // WHEN / THEN
        assertThrows(NullPointerException.class, () -> algorithmHelper.getAlgorithmName(null));
    }

    // --- getKeyAlgorithmIdentifier tests ---

    @Test
    void getKeyAlgorithmIdentifierReturnsOidForKnownName() {
        // GIVEN
        var algorithmName = "SHA256WITHECDSA";

        // WHEN
        var result = algorithmHelper.getKeyAlgorithmIdentifier(algorithmName);

        // THEN
        assertEquals(X9ObjectIdentifiers.ecdsa_with_SHA256, result);
    }

    @Test
    void getKeyAlgorithmIdentifierReturnsNullForUnknownName() {
        // WHEN
        var result = algorithmHelper.getKeyAlgorithmIdentifier("foo");

        // THEN
        assertNull(result);
    }

    @Test
    void getKeyAlgorithmIdentifierReturnsNullForNull() {
        // WHEN
        var result = algorithmHelper.getKeyAlgorithmIdentifier(null);

        // THEN
        assertNull(result);
    }

    // --- isDigestAlgorithmCompatibleWithSignatureAlgorithm tests ---

    @Test
    void isDigestCompatibleWithSignatureReturnsTrueForMatchingAlgorithms() {
        // GIVEN
        var digestOid = NISTObjectIdentifiers.id_sha256;
        var signatureOid = X9ObjectIdentifiers.ecdsa_with_SHA256;

        // WHEN
        var result = algorithmHelper.isDigestAlgorithmCompatibleWithSignatureAlgorithm(digestOid, signatureOid);

        // THEN
        assertTrue(result);
    }

    @Test
    void isDigestCompatibleWithSignatureReturnsFalseForMismatchedAlgorithms() {
        // GIVEN
        var digestOid = PKCSObjectIdentifiers.md5;
        var signatureOid = X9ObjectIdentifiers.ecdsa_with_SHA256;

        // WHEN
        var result = algorithmHelper.isDigestAlgorithmCompatibleWithSignatureAlgorithm(digestOid, signatureOid);

        // THEN
        assertFalse(result);
    }
}
