package com.czertainly.signserver.csc.signing.configuration;

import com.czertainly.signserver.csc.signing.filter.Worker;

public record WorkerWithCapabilities(Worker worker, WorkerCapabilities capabilities) {

}
