package com.czertainly.csc.providers;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;

import java.util.Map;
import java.util.function.Supplier;

public interface DistinguishedNameProvider {

    Result<String, TextError> getDistinguishedName(Supplier<Map<String, String>> keyValueSource);
}
