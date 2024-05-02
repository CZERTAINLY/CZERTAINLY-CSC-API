package com.czertainly.signserver.csc.providers;

import java.util.Map;
import java.util.function.Supplier;

public interface UsernameProvider {

    String getUsername(Supplier<Map<String, String>> keyValueSource);

}
