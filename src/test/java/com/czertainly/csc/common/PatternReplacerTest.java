package com.czertainly.csc.common;


import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PatternReplacerTest {

    PatternReplacer patternReplacer = new PatternReplacer("CN=$[UserInfo.name], UID=$[UserInfo.id]", "TestReplacer");

    @Test
    void willReplaceVariablesGivenAllAreKnown() {
        // given
        var keyValueSource = Map.of("UserInfo.name", "John", "UserInfo.id", "123");

        // when
        String replaced = patternReplacer.replacePattern(() -> keyValueSource);

        // then
        assertEquals("CN=John, UID=123", replaced);
    }

    @Test
    void willThrowExceptionWhenVariableIsNotKnown() {
        // given
        var keyValueSource = Map.of("UserInfo.name", "John");

        // when
        Executable ex = () -> patternReplacer.replacePattern(() -> keyValueSource);


        // then
        var t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals(
                "Not all variables could be replaced in the pattern provided to TestReplacer. Unknown variables: [UserInfo.id]",
                t.getMessage()
        );
    }

    @Test
    void willNotReplaceStringIfNotVariables() {
        // given
        PatternReplacer patternReplacer = new PatternReplacer("CN=UserInfo.name, UID=$[UserInfo.id]", "TestReplacer");
        var keyValueSource = Map.of("UserInfo.name", "John", "UserInfo.id", "123");

        // when
        String replaced = patternReplacer.replacePattern(() -> keyValueSource);

        // then
        assertEquals("CN=UserInfo.name, UID=123", replaced);
    }
}