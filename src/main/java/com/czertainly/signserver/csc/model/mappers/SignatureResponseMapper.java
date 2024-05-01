package com.czertainly.signserver.csc.model.mappers;

import com.czertainly.signserver.csc.common.result.ErrorWithDescription;
import com.czertainly.signserver.csc.common.result.Result;

public interface SignatureResponseMapper<IN, OUT> {

    Result<OUT, ErrorWithDescription> map(IN model);
}
