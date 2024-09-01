package com.czertainly.csc.signing.configuration;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.signing.filter.Criterion;
import com.czertainly.csc.signing.filter.Worker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;

public class WorkerRepository {

    private static final Logger logger = LoggerFactory.getLogger(WorkerRepository.class);
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

    public Result<List<CryptoToken>, TextError> getAllCryptoTokens() {
        var tokens = workersWithCapabilities.stream()
                                      .map(WorkerWithCapabilities::worker)
                                      .map(Worker::cryptoToken)
                                      .distinct()
                                      .toList();

        return Result.success(tokens);
    }

    public Result<CryptoToken, TextError> getCryptoToken(String tokenName) {
        var maybeToken = workersWithCapabilities.stream()
                                      .map(WorkerWithCapabilities::worker)
                                      .map(Worker::cryptoToken)
                                      .filter(token -> Objects.equals(token.name(), tokenName))
                                                .findFirst();

        return maybeToken
                .<Result<CryptoToken, TextError>>map(Result::success)
                .orElseGet(() -> Result.error(TextError.of("Crypto token '%s' not found.", tokenName)));
    }
}
