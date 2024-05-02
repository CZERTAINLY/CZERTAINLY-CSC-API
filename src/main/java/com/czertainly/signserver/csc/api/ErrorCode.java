package com.czertainly.signserver.csc.api;

public enum ErrorCode {
    INVALID_REQUEST("invalid_request"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    ACCESS_DENIED("access_denied"),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),
    INVALID_SCOPE("invalid_scope"),
    SERVER_ERROR("server_error"),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable"),
    EXPIRED_TOKEN("expired_token"),
    INVALID_TOKEN("invalid_token");

    private final String value;

    ErrorCode(String value) {
        this.value = value;
    }

    public static ErrorCode fromString(String value) throws IllegalArgumentException {
        for (ErrorCode code : ErrorCode.values()) {
            if (code.value.equals(value)) {
                return code;
            }
        }

        throw new IllegalArgumentException("Unknown error code '" + value + "'");
    }

    public String toString() {
        return this.value;
    }

}
