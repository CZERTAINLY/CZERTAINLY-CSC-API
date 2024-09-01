package com.czertainly.csc.api.mappers;

import com.czertainly.csc.api.mappers.MappingError.InvalidRequest;
import com.czertainly.csc.common.result.Result;

public class ApiRequestResult {

    public static <R> Result<R, ? extends MappingError> invalidRequest(String errorMessage) {
        return Result.error(new InvalidRequest(errorMessage));
    }

    public static <R> Result<R, ? extends MappingError> unauthorized(String errorMessage) {
        return Result.error(new MappingError.Unauthorized(errorMessage));
    }

}
