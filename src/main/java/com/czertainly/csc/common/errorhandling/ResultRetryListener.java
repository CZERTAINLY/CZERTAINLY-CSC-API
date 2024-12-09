package com.czertainly.csc.common.errorhandling;

import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.TextErrorWithRetryIndication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.retry.RetryCallback;
import org.springframework.retry.RetryContext;
import org.springframework.retry.RetryListener;
import org.springframework.stereotype.Component;

@Component("resultRetryListener")
public class ResultRetryListener implements RetryListener {

    private static final Logger logger = LoggerFactory.getLogger(ResultRetryListener.class);

    @Override
    public <T, E extends Throwable> void close(RetryContext context, RetryCallback<T, E> callback, Throwable throwable
    ) {
        RetryListener.super.close(context, callback, throwable);
    }

    @Override
    public <T, E extends Throwable> void onError(RetryContext context, RetryCallback<T, E> callback,
                                                 Throwable throwable
    ) {
        logger.info("Retry attempt {} failed due to: {} ({})", context.getRetryCount(), throwable.getMessage(),
                    throwable.getClass().getName()
        );
    }

    @Override
    public <T, E extends Throwable> boolean open(RetryContext context, RetryCallback<T, E> callback) {
        return RetryListener.super.open(context, callback);
    }

    @Override
    public <T, E extends Throwable> void onSuccess(RetryContext context, RetryCallback<T, E> callback, T result) {
        if (result instanceof Error(var value)) {
            if (value instanceof TextErrorWithRetryIndication textError) {
                if (textError.getShouldRetry()) {
                    throw new ErrorResultRetryException(textError);
                }
            }
            logger.info("Retry attempt {} has failed with error and will not be retried.", context.getRetryCount() + 1);
        } else {
            if (context.getRetryCount() > 0) {
                logger.debug("Retry attempt {} has succeeded.", context.getRetryCount() + 1);
            }
        }

    }
}
