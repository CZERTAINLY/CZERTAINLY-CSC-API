package com.czertainly.csc.configuration;

import com.czertainly.csc.configuration.csc.CscConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

@Configuration
@EnableAsync
@EnableConfigurationProperties(CscConfiguration.class)
public class AsyncConfig {

    private static final Logger logger = LoggerFactory.getLogger(AsyncConfig.class);

    private final CscConfiguration cscConfig;

    public AsyncConfig(CscConfiguration cscConfig) {
        this.cscConfig = cscConfig;
    }

    @Bean(name = "oneTimeKeyDeletionExecutor", destroyMethod = "close")
    public ExecutorService oneTimeKeyDeletionExecutor() {
        ThreadFactory tf = Thread.ofVirtual()
                                 .name("key-del-", 0)
                                 .uncaughtExceptionHandler(
                                         (t, e) -> logger.error(
                                                 "Uncaught exception in one-time key deletion thread: {}",
                                                 t.getName(), e
                                         ))
                                 .factory();
        ExecutorService base = Executors.newFixedThreadPool(cscConfig.concurrency().maxKeyDeletion(), tf);
        return new DelegatingSecurityContextExecutorService(base);
    }

    @Bean(name = "keyGenerationExecutor", destroyMethod = "close")
    public ExecutorService keyGenerationExecutor() {
        ThreadFactory tf = Thread.ofVirtual()
                                 .name("key-gen-", 0)
                                 .uncaughtExceptionHandler(
                                         (t, e) -> logger.error("Uncaught exception in key generation thread: {}",
                                                                t.getName(), e
                                         ))
                                 .factory();
        ExecutorService base = Executors.newFixedThreadPool(cscConfig.concurrency().maxKeyGeneration(), tf);
        return new DelegatingSecurityContextExecutorService(base);
    }

    /**
     * Global handler for uncaught exceptions in @Async void methods
     */
    @Bean
    public AsyncUncaughtExceptionHandler asyncExceptionHandler() {
        return (ex, method, params) ->
                logger.error("Uncaught async exception in {}.{}: {}",
                             method.getDeclaringClass().getSimpleName(),
                             method.getName(),
                             ex.getMessage(),
                             ex
                );
    }
}
