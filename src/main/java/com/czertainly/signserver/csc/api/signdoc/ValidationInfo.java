package com.czertainly.signserver.csc.api.signdoc;

import java.util.List;

public record ValidationInfo(
        List<String> ocsp,
        List<String> crl,
        List<String> certificates
) {
}
