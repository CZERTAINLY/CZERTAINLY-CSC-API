package com.czertainly.signserver.csc.model.mappers;

import com.czertainly.signserver.csc.api.auth.SignatureActivationData;
import com.czertainly.signserver.csc.common.ErrorWithDescription;
import com.czertainly.signserver.csc.common.Result;

public interface SignatureRequestMapper<IN, OUT> {

    Result<OUT, ErrorWithDescription> map(IN dto, SignatureActivationData sad);
}
