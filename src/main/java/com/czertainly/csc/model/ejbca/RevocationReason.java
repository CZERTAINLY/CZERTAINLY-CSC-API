package com.czertainly.csc.model.ejbca;

public enum RevocationReason {
    NOT_REVOKED(-1),
    UNSPECIFIED(0),
    KEYCOMPROMISE(1),
    CACOMPROMISE(2),
    AFFILIATIONCHANGED(3),
    SUPERSEDED(4),
    CESSATIONOFOPERATION(5),
    CERTIFICATEHOLD(6),
    REMOVEFROMCRL(8),
    PRIVILEGESWITHDRAWN(9),
    AACOMPROMISE(10);

    private final int ejbcaValue;

    RevocationReason(int code) {
        this.ejbcaValue = code;
    }

    public int getEjbcaValue() {
        return ejbcaValue;
    }
}
