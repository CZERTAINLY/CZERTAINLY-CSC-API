package com.czertainly.csc.api.mappers;

import com.czertainly.csc.common.result.ErrorWithDescription;
import com.czertainly.csc.common.result.Result;

public interface ResponseMapper<IN, OUT> {

    Result<OUT, ErrorWithDescription> map(IN model);
}
