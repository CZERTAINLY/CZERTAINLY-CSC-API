package com.czertainly.signserver.csc.signing.filter;

public interface Criterion<T> {

    boolean matches(T element);

}
