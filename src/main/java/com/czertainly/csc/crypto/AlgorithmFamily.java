package com.czertainly.csc.crypto;

/**
 * Classifies algorithm OIDs into families that determine how signature
 * algorithm unification is performed.
 *
 * <ul>
 *   <li>{@link #RSAES_PKCS1} — bare encryption algorithm (RSA); requires a separate digest OID</li>
 *   <li>{@link #RSASSA_PKCS1} — composite RSA signature algorithm that already encodes both
 *       key and digest (e.g. SHA256withRSA) — a separate key OID exists</li>
 *   <li>{@link #RSASSA_PSS} — RSASSA-PSS; requires a separate digest OID to select the MGF hash</li>
 *   <li>{@link #ECDSA} — composite ECDSA signature algorithm that encodes both
 *       key and digest (e.g. SHA256withECDSA) — no standalone key OID exists</li>
 *   <li>{@link #EdDSA} — algorithms that do not use an external digest at all
 *       (e.g. Ed25519, Ed448)</li>
 * </ul>
 */
public enum AlgorithmFamily {
    RSAES_PKCS1,
    RSASSA_PKCS1,
    RSASSA_PSS,
    ECDSA,
    EdDSA
}
