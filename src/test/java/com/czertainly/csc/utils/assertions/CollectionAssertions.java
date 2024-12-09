package com.czertainly.csc.utils.assertions;

import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CollectionAssertions {

    public static void assertContainsExactlyInAnyOrder(List<String> expected, List<String> actual) {
        assertEquals(new HashSet<>(expected), new HashSet<>(actual));
    }
}
