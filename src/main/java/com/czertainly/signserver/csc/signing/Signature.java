package com.czertainly.signserver.csc.signing;

import com.czertainly.signserver.csc.signing.configuration.SignaturePackaging;

public record Signature(
        byte[] value,
        SignaturePackaging packaging
) {
}
