package com.czertainly.csc.api.credentials;

import com.czertainly.csc.components.DateConverter;
import com.czertainly.csc.model.csc.CertificateInfo;
import com.czertainly.csc.model.csc.CertificateStatus;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Base64;
import java.util.List;

public record CertificateDto(

        @Schema(
                description = """
                        The status of validity of the end entity certificate. The value is
                        OPTIONAL, so the remote service SHOULD only return a value that is
                        accurate and consistent with the actual validity status of the certificate
                        at the time the response is generated. Possible values are:
                        "valid", "expired", "revoked", "suspended".
                        """,
                implementation = String.class,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        String status,

        @Schema(
                description = """
                        One or more Base64-encoded X.509v3 certificates from the certificate
                        chain. If the certificates parameter is “chain”, the entire certificate chain
                        SHALL be returned with the end entity certificate at the beginning of the
                        array. If the certificates parameter is “single”, only the end entity
                        certificate SHALL be returned. If the certificates parameter is “none”, this
                        value SHALL NOT be returned.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED,
                implementation = String.class
        )
        List<String> certificates,

        @Schema(
                description = """
                        The Issuer Distinguished Name from the X.509v3 end entity certificate as
                        UTF-8-encoded character string according to RFC 4514. This value
                        SHALL be returned when certInfo is “true”.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED,
                implementation = String.class
        )
        String issuerDN,

        @Schema(
                description = """
                        The Serial Number from the X.509v3 end entity certificate represented
                        as hex-encoded string format. This value SHALL be returned when
                        certInfo is “true”.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED,
                implementation = String.class
        )
        String serialNumber,

        @Schema(
                description = """
                        The Subject Distinguished Name from the X.509v3 end entity certificate
                        as UTF-8-encoded character string, according to RFC 4514. This value
                        SHALL be returned when certInfo is “true”.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED,
                implementation = String.class
        )
        String subjectDN,

        @Schema(
                description = """
                        The validity start date from the X.509v3 end entity certificate as
                        character string, encoded as GeneralizedTime (RFC 5280)
                        (e.g. “YYYYMMDDHHMMSSZ”). This value SHALL be returned when
                        certInfo is “true”
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED,
                implementation = String.class
        )
        String validFrom,

        @Schema(
                description = """
                        The validity end date from the X.509v3 end entity certificate as character
                        string, encoded as GeneralizedTime (RFC 5280 [8])
                        (e.g. “YYYYMMDDHHMMSSZ”). This value SHALL be returned when
                        certInfo is “true”.
                        """,
                requiredMode = Schema.RequiredMode.NOT_REQUIRED,
                implementation = String.class
        )
        String validTo
) {

    public static CertificateDto fromModel(CertificateInfo certificateInfo, DateConverter dateConverter) {
        Base64.Encoder encoder = Base64.getEncoder();
        List<String> certificates = certificateInfo.certificates()
                                                   .stream()
                                                   .map(certificate -> new String(encoder.encode(certificate)))
                                                   .toList();
        return new CertificateDto(
                certificateStatusToString(certificateInfo.status()),
                certificates,
                certificateInfo.issuerDN(),
                certificateInfo.serialNumber(),
                certificateInfo.subjectDN(),
                dateConverter.toGeneralizedTimeString(certificateInfo.validFrom()),
                dateConverter.toGeneralizedTimeString(certificateInfo.validTo())
        );
    }

    private static String certificateStatusToString(CertificateStatus certificate) {
        return switch (certificate) {
            case NOT_YET_VALID -> "not yet valid";
            case VALID -> "valid";
            case EXPIRED -> "expired";
            case REVOKED -> "revoked";
            case SUSPENDED -> "suspended";
        };
    }

}
