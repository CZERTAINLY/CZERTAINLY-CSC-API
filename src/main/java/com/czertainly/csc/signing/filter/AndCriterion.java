package com.czertainly.csc.signing.filter;

import java.util.ArrayList;
import java.util.List;

public class AndCriterion<T> implements Criterion<T> {

    private final List<Criterion<T>> criteria;

    public AndCriterion() {
        this.criteria = new ArrayList<>();
    }

    public AndCriterion(List<Criterion<T>> criteria) {
        this.criteria = criteria;
    }

    public void add(Criterion<T> criterion) {
        criteria.add(criterion);
    }

    @Override
    public boolean matches(T element) {
        return criteria.stream().allMatch(criterion -> criterion.matches(element));
    }
}
