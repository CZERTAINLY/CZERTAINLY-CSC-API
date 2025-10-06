package com.czertainly.csc.api.credentials;

import com.czertainly.csc.model.csc.KeyInfo;
import com.czertainly.csc.model.csc.KeyStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.lang.Nullable;

import java.util.List;

public record KeyDto(

        @Schema(
                description = """
                        The status of the signing key of the credential:
                        “enabled”: the signing key is enabled and can be used for signing.
                        “disabled”: the signing key is disabled and cannot be used for signing. This MAY occur when
                            the owner has disabled it or when the RSSP has detected that the associated certificate is
                            expired or revoked.
                        """,
                implementation = String.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String status,

        @Schema(
                description = """
                        The list of OIDs of the supported key algorithms. For example:
                        1.2.840.113549.1.1.1 = RSA encryption, 1.2.840.10045.4.3.2 = ECDSA with SHA256.
                        """,
                implementation = String.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        List<String> algo,

        @Schema(
                description = """
                        The length of the cryptographic key in bits.
                        """,
                implementation = String.class,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        @Nullable Integer len,

        @Schema(
                description = """
                        The OID of the ECDSA curve. The value SHALL only be returned if
                        keyAlgo is based on ECDSA.
                        """,
                implementation = String.class,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED
        )
        @Nullable String curve
) {

    public static KeyDto fromModel(KeyInfo keyInfo) {
        return new KeyDto(
                keyStatusToString(keyInfo.status()),
                keyInfo.algo().stream().map(Object::toString).toList(),
                keyInfo.len(),
                keyInfo.curve()
        );
    }

    private static String keyStatusToString(KeyStatus keyStatus) {
        return switch (keyStatus) {
            case ENABLED -> "enabled";
            case DISABLED -> "disabled";
        };
    }
}
