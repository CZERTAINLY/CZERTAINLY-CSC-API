package com.czertainly.csc.api.signdoc;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Set;

public record ValidationInfo(

        @Schema(
                description = """
                        Array of Base64-encoded strings containing the DER-encoded ASN.1 data
                        structures of type `CertificateList` according to [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).
                        """
        )
        Set<String> crl,

        @Schema(
                description = """
                        Array of Base64-encoded strings containing the DER-encoded ASN.1 data
                        structures of type `OCSPResponse` according to [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960).
                        """
        )
        Set<String> ocsp,

        @Schema(
                description = """
                        Array of Base64-encoded X.509v3 certificates from the certificate
                        chain used to create the respective signature and timestamps included in the signature.
                        """
        )
        Set<String> certificates
) {
}
