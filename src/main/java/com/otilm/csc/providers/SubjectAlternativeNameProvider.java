package com.otilm.csc.providers;

import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;

import java.util.Map;
import java.util.function.Supplier;

public interface SubjectAlternativeNameProvider {

    Result<String, TextError> getSan(Supplier<Map<String, String>> keyValueSource);

}
