package com.czertainly.csc.configuration;

import com.czertainly.csc.configuration.csc.CscConfiguration;
import com.czertainly.csc.configuration.csc.OneTimeKeysExecutorSettings;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

@Configuration
@EnableConfigurationProperties(CscConfiguration.class)
public class AsyncConfig {

    @Bean(name = "oneTimeKeyExecutor")
    public Executor oneTimeKeyExecutor(CscConfiguration settings) {
        OneTimeKeysExecutorSettings exec = settings.oneTimeKeys().cleanupExecutor();
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(exec.coreSize());
        executor.setMaxPoolSize(exec.maxSize());
        executor.setQueueCapacity(exec.queueCapacity());
        executor.setThreadNamePrefix(exec.threadNamePrefix());
        executor.initialize();
        return executor;
    }

}
