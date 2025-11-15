package com.czertainly.csc.signing.configuration;

import java.util.Arrays;

public enum AttributeName {
    COMMITMENT_TYPE_INDICATION("commitment-type-indication",
                               "Base64-encoding of the attribute commitment-type-indication defined in clause 5.2.3 of ETSI EN 319 122-1"
    ),
    CONTENT_HINT("content-hint",
                 "Base64-encoding of the attribute content-hint defined in clause 5.2.4.1 of ETSI EN 319 122-1"
    ),
    MIME_TYPE("mime-type", "Base64-encoding of the attribute mime-type defined in clause 5.4.2.2 of ETSI EN 319 122-1"),
    SIGNER_LOCATION("signer-location",
                    "Base64-encoding of the attribute signer-location defined in clause 5.2.5 of ETSI EN 319 122-1"
    ),
    CONTENT_TIME_STAMP("content-time-stamp",
                       "Base64-encoding of the attribute content-time-stamp defined in clause 5.2.8 of ETSI EN 319 122-1"
    ),
    SIGNER_ATTRIBUTES_V2("signer-attributes-v2",
                         "Base64-encoding of the attribute signer-attributes-v2 defined in clause 5.2.6.1 of ETSI EN 319 122-1"
    ),
    SIGNATURE_POLICY_IDENTIFIER("signature-policy-identifier",
                                "Base64-encoding of the attribute signature-policy-identifier defined in clause 5.2.9.1 of ETSI EN 319 122-1"
    ),
    CONTENT_REFERENCE("content-reference",
                      "Base64-encoding of the attribute content-reference defined in clause 5.2.11 of ETSI EN 319 122-1"
    ),
    CONTENT_IDENTIFIER("content-identifier",
                       "Base64-encoding of the attribute content-identifier defined in clause 5.2.12 of ETSI EN 319 122-1"
    ),
    LOCATION("location", "Base64-encoding of the attribute Location defined in clause 5.3 of ETSI EN 319 142-1"),
    REASON("reason", "Base64-encoding of the attribute Reason defined in clause 5.3 of ETSI EN 319 142-1"),
    NAME("name", "Base64-encoding of the attribute Name defined in clause 5.3 of ETSI EN 319 142-1"),
    CONTACTINFO("contactInfo",
                "Base64-encoding of the attribute ContactInfo defined in clause 5.3 of ETSI EN 319 142-1 "
    ),
    SIGNERROLEV2("signerRoleV2",
                 "Base64-encoding of the attribute SignerRoleV2 defined in clause 5.2.6 of ETSI EN 319 132-1"
    ),
    COMMITMENTTYPEINDICATION("commitmentTypeIndication",
                             "Base64-encoding of the attribute CommitmentTypeIndication defined in clause 5.2.3 of ETSI EN 319 132-1"
    ),
    SIGNATUREPRODUCTIONPLACEV2("signatureProductionPlaceV2",
                               "Base64-encoding of the attribute SignatureProductionPlaceV2 defined in clause 5.2.5 of ETSI EN 319 132-1"
    ),
    ALLDATAOBJECTSTIMESTAMP("allDataObjectsTimeStamp",
                            "Base64-encoding of the attribute AllDataObjectsTimeStamp defined in clause 5.2.8.1 of ETSI EN 319 132-1"
    ),
    INDIVIDUALDATAOBJECTSTIMESTAMP("individualDataObjectsTimeStamp",
                                   "Base64-encoding of the attribute IndividualDataObjectsTimeStamp defined in clause 5.2.8.2 of ETSI EN 319 132-1"
    ),
    SIGNATUREPOLICYIDENTIFIER("signaturePolicyIdentifier",
                              "Base64-encoding of the attribute SignaturePolicyIdentifier defined in clause 5.2.9 of ETSI EN 319 132-1"
    );

    private final String value;
    private final String description;

    AttributeName(String value, String description) {
        this.value = value;
        this.description = description;
    }

    public static AttributeName fromString(String value) throws IllegalArgumentException {
        for (AttributeName format : AttributeName.values()) {
            if (format.value.equals(value)) {
                return format;
            }
        }

        return switch (value) {
            case "commitment-type-indication" -> COMMITMENT_TYPE_INDICATION;
            default -> throw new IllegalArgumentException(
                    "Unknown attribute name '" + value + "'. Allowed values: [" + String.join(",", Arrays.toString(
                            AttributeName.values())
                    ) + "]");
        };
    }

    public String toString() {
        return this.value;
    }

}
