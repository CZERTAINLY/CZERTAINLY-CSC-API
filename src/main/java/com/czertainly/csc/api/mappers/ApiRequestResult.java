package com.czertainly.csc.api.mappers;

import com.czertainly.csc.common.result.ErrorWithDescription;
import com.czertainly.csc.common.result.Result;

public class ApiRequestResult {

    public static final String INVALID_REQUEST = "invalid_request";

    public static <R> Result<R, ErrorWithDescription> invalidRequest(String errorMessage) {
        return Result.error(new ErrorWithDescription(INVALID_REQUEST, errorMessage));
    }

}
