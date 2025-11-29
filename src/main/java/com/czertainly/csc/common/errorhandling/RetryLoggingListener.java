package com.czertainly.csc.common.errorhandling;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.retry.RetryCallback;
import org.springframework.retry.RetryContext;
import org.springframework.retry.RetryListener;
import org.springframework.stereotype.Component;

@Component("retryLoggingListener")
public class RetryLoggingListener implements RetryListener {

    private static final Logger logger = LoggerFactory.getLogger(RetryLoggingListener.class);

    @Override
    public <T, E extends Throwable> void onError(RetryContext context, RetryCallback<T, E> callback,
                                                 Throwable throwable
    ) {
        logger.info("Retry attempt {} failed due to: {} ({})", context.getRetryCount(), throwable.getMessage(),
                    throwable.getClass().getName()
        );
    }

    @Override
    public <T, E extends Throwable> void onSuccess(RetryContext context, RetryCallback<T, E> callback, T result) {
        if (context.getRetryCount() > 0) {
            logger.debug("Attempt {} has succeeded.", context.getRetryCount() + 1);
        }
    }

    @Override
    public <T, E extends Throwable> boolean open(RetryContext context, RetryCallback<T, E> callback) {
        return RetryListener.super.open(context, callback);
    }

    @Override
    public <T, E extends Throwable> void close(RetryContext context, RetryCallback<T, E> callback, Throwable throwable
    ) {
        RetryListener.super.close(context, callback, throwable);
    }
}