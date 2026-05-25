package com.otilm.csc.signing.configuration;

import com.otilm.csc.signing.filter.Worker;

public record WorkerWithCapabilities(Worker worker, WorkerCapabilities capabilities) {

}
