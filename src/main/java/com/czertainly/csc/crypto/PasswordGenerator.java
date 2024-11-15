package com.czertainly.csc.crypto;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;

public interface PasswordGenerator {

    Result<String, TextError> generate();

}
