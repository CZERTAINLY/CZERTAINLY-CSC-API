package com.czertainly.csc.signing.filter;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


class AndCriterionTest {


    @Test
    void matchesReturnsTrueOnAllMatchingCriteria() {
        // given
        var c1 = new TestBooleanCriterion(true);
        var c2 = new TestBooleanCriterion(true);
        AndCriterion<Boolean> andCriterion = new AndCriterion<>(List.of(c1, c2));

        // when
        boolean isMatch = andCriterion.matches(true);

        // then
        assertTrue(isMatch);
    }

    @Test
    void matchesReturnsFalseOnOneOrMoreNoneMatchingCriteria() {
        // given
        var c1 = new TestBooleanCriterion(true);
        var c2 = new TestBooleanCriterion(false);
        AndCriterion<Boolean> andCriterion = new AndCriterion<>(List.of(c1, c2));

        // when
        boolean isMatch = andCriterion.matches(true);

        // then
        assertFalse(isMatch);
    }


    static class TestBooleanCriterion implements Criterion<Boolean> {

        private final boolean shouldMatch;

        public TestBooleanCriterion(boolean shouldMatch) {
            this.shouldMatch = shouldMatch;
        }

        @Override
        public boolean matches(Boolean element) {
            return shouldMatch;
        }
    }

}