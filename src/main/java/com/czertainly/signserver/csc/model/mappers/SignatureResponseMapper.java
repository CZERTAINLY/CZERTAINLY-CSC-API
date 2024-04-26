package com.czertainly.signserver.csc.model.mappers;

import com.czertainly.signserver.csc.api.auth.SignatureActivationData;
import com.czertainly.signserver.csc.common.ErrorWithDescription;
import com.czertainly.signserver.csc.common.Result;

public interface SignatureResponseMapper<IN, OUT> {

    Result<OUT, ErrorWithDescription> map(IN model);
}
