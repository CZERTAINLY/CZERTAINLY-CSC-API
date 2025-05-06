package com.czertainly.csc.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

@Configuration
@EnableAsync
public class AsyncConfig {

    private static final Logger logger = LoggerFactory.getLogger(AsyncConfig.class);

    @Bean(name = "oneTimeKeyDeletionExecutor", destroyMethod = "close")
    public ExecutorService oneTimeKeyDeletionExecutor() {
        ThreadFactory tf = Thread.ofVirtual()
                .name("key-del-", 0)
                .factory();
        ExecutorService base = Executors.newThreadPerTaskExecutor(tf);
        return new DelegatingSecurityContextExecutorService(base);
    }

    /** Global handler for uncaught exceptions in @Async void methods */
    @Bean
    public AsyncUncaughtExceptionHandler asyncExceptionHandler() {
        return (ex, method, params) ->
                logger.error("Uncaught async exception in {}.{}: {}",
                        method.getDeclaringClass().getSimpleName(),
                        method.getName(),
                        ex.getMessage(),
                        ex);
    }
}
