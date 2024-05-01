package com.czertainly.signserver.csc.crypto;

import org.springframework.stereotype.Component;

@Component
public class NaivePasswordGenerator implements PasswordGenerator {

    @Override
    public String generate() {
        return "password";
    }
}
