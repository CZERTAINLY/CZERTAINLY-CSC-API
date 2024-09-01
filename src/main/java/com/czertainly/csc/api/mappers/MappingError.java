package com.czertainly.csc.api.mappers;

import com.czertainly.csc.common.result.ExtendableErrorValue;

public sealed class MappingError extends ExtendableErrorValue<String> permits MappingError.InvalidRequest, MappingError.Unauthorized {

    MappingError(String text) {
        super(text);
    }

    @Override
    public MappingError extend(String error) {
        return null;
    }

    public static final class InvalidRequest extends MappingError {
        public InvalidRequest(String errorMessage) {
            super(errorMessage);
        }
    }

    public static final class Unauthorized extends MappingError {
        public Unauthorized(String errorMessage) {
            super(errorMessage);
        }
    }
}
