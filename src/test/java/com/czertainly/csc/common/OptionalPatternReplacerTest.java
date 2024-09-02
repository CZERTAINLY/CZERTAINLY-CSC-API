package com.czertainly.csc.common;

import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OptionalPatternReplacerTest {

    Map<String, String> keyValueSource = Map.of("UserInfo.name", "John", "UserInfo.id", "123");

    @Test
    void canReplacePattern() {
        // given
        var pattern = "CN=$[UserInfo.name], UID=$[UserInfo.id]";
        var requiredComponents = List.of("CN", "DN");

        // setup
        var replacer = new OptionalPatternReplacer(pattern, requiredComponents, "TestReplacer");

        // when
        String replaced = replacer.replacePattern(() -> keyValueSource);

        // then

        assertEquals("CN=John, UID=123", replaced);
    }

    @Test
    void optionalComponentsAreSkippedWhenValueNotAvailable() {
        // given
        var pattern = "CN=$[UserInfo.name], UID=$[UserInfo.id], OPT=$[UserInfo.opt]";
        var requiredComponents = List.of("CN");

        // setup
        var replacer = new OptionalPatternReplacer(pattern, requiredComponents, "TestReplacer");

        // when
        String replaced = replacer.replacePattern(() -> keyValueSource);

        // then
        assertEquals("CN=John, UID=123", replaced);
    }

    @Test
    void missingValueForRequiredComponentsCausesError() {
        // given
        var pattern = "CN=$[UserInfo.name], UID=$[UserInfo.id], REQ=$[UserInfo.req]";
        var requiredComponents = List.of("CN", "REQ");

        // setup
        var replacer = new OptionalPatternReplacer(pattern, requiredComponents, "TestReplacer");

        // when
        Executable replace = () -> replacer.replacePattern(() -> keyValueSource);

        // then

        assertThrows(InvalidInputDataException.class, replace);
    }

}