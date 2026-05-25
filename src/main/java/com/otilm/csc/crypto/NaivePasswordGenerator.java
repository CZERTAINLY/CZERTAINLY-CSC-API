package com.otilm.csc.crypto;

import com.otilm.csc.common.result.Result;
import com.otilm.csc.common.result.TextError;
import org.springframework.stereotype.Component;

@Component
public class NaivePasswordGenerator implements PasswordGenerator {

    @Override
    public Result<String, TextError> generate() {
        return Result.success("password");
    }
}
