package com.czertainly.csc.model;

import java.util.List;

public interface SignaturesContainer<S extends Signature> {

    List<S> signatures();

    void extend(SignaturesContainer<S> sigs);
}
