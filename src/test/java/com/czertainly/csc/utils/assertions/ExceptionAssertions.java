package com.czertainly.csc.utils.assertions;

import org.junit.jupiter.api.function.Executable;
import org.opentest4j.AssertionFailedError;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ExceptionAssertions {

    public static <T extends Throwable> void assertThrowsWithMessage(
            String expectedMessage, Class<T> clazz, Executable executable
    ) {
        var e = assertThrows(clazz, executable);
        assertEquals(expectedMessage, e.getMessage());
    }

    public static <T extends Throwable> void assertThrowsAndMessageContains(
            Class<T> clazz, String expectedMessage, Executable executable
    ) {
        var e = assertThrows(clazz, executable);
        if (!e.getMessage().contains(expectedMessage)) {
            throw new AssertionFailedError("An exception message was expected to contain a following string.",
                                           expectedMessage, e.getMessage()
            );
        }
    }
}
