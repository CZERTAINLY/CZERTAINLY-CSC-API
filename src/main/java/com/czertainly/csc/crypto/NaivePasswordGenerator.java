package com.czertainly.csc.crypto;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import org.springframework.stereotype.Component;

@Component
public class NaivePasswordGenerator implements PasswordGenerator {

    @Override
    public Result<String, TextError> generate() {
        return Result.success("password");
    }
}
