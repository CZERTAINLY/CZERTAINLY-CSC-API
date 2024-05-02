package com.czertainly.signserver.csc.api.signdoc;

import com.czertainly.signserver.csc.signing.configuration.ConformanceLevel;
import com.czertainly.signserver.csc.signing.configuration.SignatureFormat;
import com.czertainly.signserver.csc.signing.configuration.SignaturePackaging;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;
import java.util.Optional;

public class BaseDocumentDto {

    @JsonProperty("signature_format")
    @Schema(
            description = """
                    Requested signature format:
                    - `C`: CAdES signature format
                    - `X`: XAdES signature format
                    - `P`: PAdES signature format
                    - `J`: JAdES signature format
                    """,
            implementation = SignatureFormat.class,
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private final String signatureFormat;

    @JsonProperty("conformance_level")
    @Schema(
            description = """
                    Requested signature conformance level:
                    - `Ades-B-B` - baseline 191x2 level B signature
                    - `Ades-B-T` - baseline 191x2 level T signature
                    - `Ades-B-LT` - baseline 191x2 level LT signature
                    - `Ades-B-LTA` - baseline 191x2 level LTA signature
                    - `Ades-B` - baseline etsits level B signature
                    - `Ades-T` - baseline etsits level T signature
                    - `Ades-LT` - baseline etsits level LT signature
                    - `Ades-LTA` - baseline etsits level LTA signature
                    """,
            defaultValue = "Ades-B-B",
            implementation = ConformanceLevel.class
    )
    private final String conformanceLevel;

    @Schema(
            description = """
                    The OID of the algorithm to use for signing. If the parameter `hashAlgorithmOID` defined in
                    is passed, it must use the same algorithms as this parameter.
                    """,
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private final String signAlgo;

    @Schema(
            description = """
                    The Base64-encoded DER-encoded ASN.1 signature parameters, if required by
                    the `signAlgo`.
                    """
    )
    private final String signAlgoParams;

    @JsonProperty("signed_props")
    @Schema(
            description = """
                    List of signed attributes to be included in the signature.
                    """
    )
    private final List<AttributeDto> signedAttributes;

    @JsonProperty("signed_envelope_property")
    @Schema(
            description = """
                    The signature packaging format to be used. Depending on the `signature_format`, one of the following
                    values must be used:
                    - CAdES: `Detached`, `Attached`, `Parallel`
                    - PAdES: `Certification`, `Revision`
                    - XAdES: `Enveloped`, `Enveloping`, `Detached`
                    - JAdES: `Detached`, `Attached`, `Parallel`
                    """,
            implementation = SignaturePackaging.class
    )
    private final String signaturePackaging;


    public BaseDocumentDto(String signatureFormat, String conformanceLevel, String signAlgo,
                       String signAlgoParams, List<AttributeDto> signedAttributes, String signaturePackaging
    ) {
        this.signatureFormat = signatureFormat;
        this.conformanceLevel = conformanceLevel;
        this.signAlgo = signAlgo;
        this.signAlgoParams = signAlgoParams;
        this.signedAttributes =  signedAttributes == null ? List.of() : signedAttributes;
        this.signaturePackaging = signaturePackaging;
    }

    public Optional<String> getSignatureFormat() {
        return Optional.ofNullable(signatureFormat);
    }

    public Optional<String> getConformanceLevel() {
        return Optional.ofNullable(conformanceLevel);
    }

    public Optional<String> getSignAlgo() {
        return Optional.ofNullable(signAlgo);
    }

    public Optional<String> getSignAlgoParams() {
        return Optional.ofNullable(signAlgoParams);
    }

    public List<AttributeDto> getSignedAttributes() {
        return signedAttributes;
    }

    public Optional<String> getSignaturePackaging() {
        return Optional.ofNullable(signaturePackaging);
    }

}
