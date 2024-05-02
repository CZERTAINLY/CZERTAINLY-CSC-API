package com.czertainly.signserver.csc.providers;

import java.util.Map;
import java.util.function.Supplier;

public interface DistinguishedNameProvider {

    String getDistinguishedName(Supplier<Map<String, String>> keyValueSource);
}
