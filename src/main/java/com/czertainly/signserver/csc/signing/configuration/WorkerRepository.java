package com.czertainly.signserver.csc.signing.configuration;

import com.czertainly.signserver.csc.signing.filter.Criterion;

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

}
