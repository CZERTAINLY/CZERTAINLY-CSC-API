package com.czertainly.csc.signing.configuration;

import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.signing.filter.Criterion;
import com.czertainly.csc.signing.filter.Worker;

import java.util.List;
import java.util.Objects;

public class WorkerRepository {
    private final List<WorkerWithCapabilities> workersWithCapabilities;

    public WorkerRepository(List<WorkerWithCapabilities> workersWithCapabilities) {
        this.workersWithCapabilities = workersWithCapabilities;
    }

    public WorkerWithCapabilities selectWorker(Criterion<WorkerCapabilities> desiredCapabilities) {
        return workersWithCapabilities.stream()
                                      .filter(worker -> desiredCapabilities.matches(worker.capabilities()))
                                      .findFirst()
                                      .orElse(null);
    }

    public WorkerWithCapabilities getWorker(int workerId) {
        return workersWithCapabilities.stream()
                                      .filter(worker -> worker.worker().workerId() == workerId)
                                      .findFirst()
                                      .orElse(null);
    }

    public WorkerWithCapabilities getWorker(String workerName) {
        return workersWithCapabilities.stream()
                                      .filter(worker -> Objects.equals(worker.worker().workerName(), workerName))
                                      .findFirst()
                                      .orElse(null);
    }

    public List<WorkerWithCapabilities> getAllWorkers() {
        return workersWithCapabilities;
    }

    public CryptoToken getCryptoToken(String tokenName) {
        return workersWithCapabilities.stream()
                                      .map(WorkerWithCapabilities::worker)
                                      .map(Worker::cryptoToken)
                                      .filter(token -> Objects.equals(token.name(), tokenName))
                                      .findFirst()
                                      .orElse(null);
    }

}
