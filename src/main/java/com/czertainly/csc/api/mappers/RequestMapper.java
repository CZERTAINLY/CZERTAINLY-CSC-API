package com.czertainly.csc.api.mappers;

import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.common.result.ErrorWithDescription;
import com.czertainly.csc.common.result.Result;

public interface RequestMapper<IN, OUT> {

    Result<OUT, ErrorWithDescription> map(IN dto, SignatureActivationData sad);
}
