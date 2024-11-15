package com.czertainly.csc.providers;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;

import java.util.Map;
import java.util.function.Supplier;

public interface UsernameProvider {

    Result<String, TextError> getUsername(Supplier<Map<String, String>> keyValueSource);

}
