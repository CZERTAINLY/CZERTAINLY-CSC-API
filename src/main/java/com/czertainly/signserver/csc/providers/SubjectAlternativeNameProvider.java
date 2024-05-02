package com.czertainly.signserver.csc.providers;

import java.util.Map;
import java.util.function.Supplier;

public interface SubjectAlternativeNameProvider {

    String getSan(Supplier<Map<String, String>> keyValueSource);

}
