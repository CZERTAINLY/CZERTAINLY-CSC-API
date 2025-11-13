package com.czertainly.csc.common.utils;

import io.micrometer.common.lang.NonNull;

public final class ThrowableUtil {

    private ThrowableUtil() {}

    public static String chainedString(@NonNull Throwable throwable) {
        StringBuilder SB = new StringBuilder(throwable.toString());
        while ((throwable = throwable.getCause()) != null)
            SB.append(": ").append(throwable);
        return SB.toString();
    }

    public static String chainedString(@NonNull String msg, @NonNull Throwable throwable) {
        StringBuilder SB = new StringBuilder(msg);
        do {
            SB.append(": ").append(throwable);
        } while ((throwable = throwable.getCause()) != null);
        return SB.toString();
    }
}