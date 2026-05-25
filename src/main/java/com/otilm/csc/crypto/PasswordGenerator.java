package com.otilm.csc.crypto;

import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;

public interface PasswordGenerator {

    Result<String, TextError> generate();

}
