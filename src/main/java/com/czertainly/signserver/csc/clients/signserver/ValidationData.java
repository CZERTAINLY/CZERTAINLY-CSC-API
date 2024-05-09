package com.czertainly.signserver.csc.clients.signserver;

import java.util.List;

public record ValidationData(List<String> crl, List<String> ocsp, List<String> certificates) {
}
