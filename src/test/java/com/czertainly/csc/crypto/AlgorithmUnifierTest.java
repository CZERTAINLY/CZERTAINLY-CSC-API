package com.czertainly.csc.crypto;

import com.czertainly.csc.common.result.Result;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import static com.czertainly.csc.utils.assertions.ResultAssertions.assertErrorAndGet;
import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

@ExtendWith(MockitoExtension.class)
class AlgorithmUnifierTest {

    @Spy
    private AlgorithmHelper algorithmHelper = new AlgorithmHelper();

    @InjectMocks
    private AlgorithmUnifier algorithmUnifier;

    // --- KEY_AND_HASH family ---

    @Test
    void unifyWithSignatureAlgorithm() {
        // GIVEN
        String signAlgoOid = X9ObjectIdentifiers.ecdsa_with_SHA256.getId();

        // WHEN
        Result<SignatureAlgorithm, AlgorithmUnificationError> result = algorithmUnifier.unify(signAlgoOid, null);

        // THEN
        SignatureAlgorithm algo = assertSuccessAndGet(result);
        assertEquals("SHA256", algo.digestAlgorithm());
        assertEquals("ECDSA", algo.encryptionAlgorithm());
    }

    @Test
    void unifyWithIncompatibleAlgorithms() {
        // GIVEN
        String signAlgoOid = X9ObjectIdentifiers.ecdsa_with_SHA256.getId();
        String hashAlgoOid = PKCSObjectIdentifiers.md5.getId();

        // WHEN
        Result<SignatureAlgorithm, AlgorithmUnificationError> result = algorithmUnifier.unify(signAlgoOid, hashAlgoOid);

        // THEN
        var error = assertErrorAndGet(result);
        assertInstanceOf(AlgorithmUnificationError.IncompatibleAlgorithms.class, error);
    }

    // --- KEY family ---

    @Test
    void unifyWithKeyAlgorithm() {
        // GIVEN
        String keyAlgoOid = PKCSObjectIdentifiers.rsaEncryption.getId();
        String hashAlgoOid = NISTObjectIdentifiers.id_sha256.getId();

        // WHEN
        Result<SignatureAlgorithm, AlgorithmUnificationError> result = algorithmUnifier.unify(keyAlgoOid, hashAlgoOid);

        // THEN
        SignatureAlgorithm algo = assertSuccessAndGet(result);
        assertEquals("SHA256", algo.digestAlgorithm());
        assertEquals("RSA", algo.encryptionAlgorithm());
    }

    @Test
    void unifyWithMissingDigestAlgorithm() {
        // GIVEN
        String keyAlgoOid = PKCSObjectIdentifiers.rsaEncryption.getId();

        // WHEN
        Result<SignatureAlgorithm, AlgorithmUnificationError> result = algorithmUnifier.unify(keyAlgoOid, null);

        // THEN
        var error = assertErrorAndGet(result);
        assertInstanceOf(AlgorithmUnificationError.DigestAlgorithmMissing.class, error);
    }

    // --- PSS family ---

    @Test
    void unifyWithPssAndDigestReturnsSuccess() {
        // GIVEN
        String pssOid = PKCSObjectIdentifiers.id_RSASSA_PSS.getId();
        String hashAlgoOid = NISTObjectIdentifiers.id_sha256.getId();

        // WHEN
        Result<SignatureAlgorithm, AlgorithmUnificationError> result = algorithmUnifier.unify(pssOid, hashAlgoOid);

        // THEN
        SignatureAlgorithm algo = assertSuccessAndGet(result);
        assertInstanceOf(PssSignatureAlgo.class, algo);
        assertEquals("RSASSA-PSS", algo.encryptionAlgorithm());
        assertEquals("SHA256", algo.digestAlgorithm());
        assertEquals("SHA256withRSAandMGF1", algo.toJavaName());
    }

    @Test
    void unifyWithPssWithoutDigestReturnsDigestMissing() {
        // GIVEN
        String pssOid = PKCSObjectIdentifiers.id_RSASSA_PSS.getId();

        // WHEN
        Result<SignatureAlgorithm, AlgorithmUnificationError> result = algorithmUnifier.unify(pssOid, null);

        // THEN
        var error = assertErrorAndGet(result);
        assertInstanceOf(AlgorithmUnificationError.DigestAlgorithmMissing.class, error);
    }

    // --- PURE family ---

    @Test
    void unifyWithEd25519WithoutDigestReturnsSuccess() {
        // GIVEN
        String ed25519Oid = EdECObjectIdentifiers.id_Ed25519.getId();

        // WHEN
        Result<SignatureAlgorithm, AlgorithmUnificationError> result = algorithmUnifier.unify(ed25519Oid, null);

        // THEN
        SignatureAlgorithm algo = assertSuccessAndGet(result);
        assertInstanceOf(PureSignatureAlgo.class, algo);
        assertEquals("ED25519", algo.encryptionAlgorithm());
        assertNull(algo.digestAlgorithm());
        assertEquals("ED25519", algo.toJavaName());
    }

    @Test
    void unifyWithEd25519WithDigestReturnsDigestNotAllowed() {
        // GIVEN
        String ed25519Oid = EdECObjectIdentifiers.id_Ed25519.getId();
        String hashAlgoOid = NISTObjectIdentifiers.id_sha256.getId();

        // WHEN
        Result<SignatureAlgorithm, AlgorithmUnificationError> result = algorithmUnifier.unify(ed25519Oid, hashAlgoOid);

        // THEN
        var error = assertErrorAndGet(result);
        assertInstanceOf(AlgorithmUnificationError.DigestAlgorithmNotAllowed.class, error);
    }

    // --- Unknown / error cases ---

    @Test
    void unifyWithUnknownSignatureReturnsUnsupportedAlgorithm() {
        // GIVEN
        String signAlgoOid = "1.2.3.4.5.6.7";

        // WHEN
        Result<SignatureAlgorithm, AlgorithmUnificationError> result = algorithmUnifier.unify(signAlgoOid, null);

        // THEN
        var error = assertErrorAndGet(result);
        assertInstanceOf(AlgorithmUnificationError.UnsupportedAlgorithm.class, error);
    }

    @Test
    void unifyWithIllegalArgumentException() {
        // GIVEN
        String invalidOid = "NOT_AN_OID";

        // WHEN
        Result<SignatureAlgorithm, AlgorithmUnificationError> result = algorithmUnifier.unify(invalidOid, null);

        // THEN
        var error = assertErrorAndGet(result);
        assertInstanceOf(AlgorithmUnificationError.OtherError.class, error);
    }
}
