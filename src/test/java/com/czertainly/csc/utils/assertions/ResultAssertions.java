package com.czertainly.csc.utils.assertions;

import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;

public class ResultAssertions {

    public static void assertSuccess(Result<?, TextError> result) {
        if (result instanceof Error(var e)) {
            throw new AssertionError(String.format("Expected success but got error with message: %s", e));
        }
    }

    public static <T> T assertSuccessAndGet(Result<T, TextError> result) {
        assertSuccess(result);
        return result.unwrap();
    }

    public static void assertErrorContains(Result<?, TextError> result, String expectedErrorMessageFragment) {
        if (result instanceof Error(var e)) {
            if (!e.toString().contains(expectedErrorMessageFragment)) {
                throw new AssertionError(
                        String.format(
                                "Expected error message to contain string '%s' but got '%s'",
                                expectedErrorMessageFragment, e
                        )
                );
            }
        } else {
            throw new AssertionError("Expected Error but got Success.");
        }
    }

    public static void assertError(Result<?, TextError> result) {
        if (result instanceof Error) {
            return;
        }
        throw new AssertionError("Expected Error but got Success.");
    }
}
