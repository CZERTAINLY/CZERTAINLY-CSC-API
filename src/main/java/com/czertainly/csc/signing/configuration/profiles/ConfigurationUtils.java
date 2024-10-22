package com.czertainly.csc.signing.configuration.profiles;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import org.springframework.lang.NonNull;

import java.io.File;
import java.time.Duration;
import java.util.function.Supplier;

public class ConfigurationUtils {

    public static Result<File, TextError> checkFileExistenceAndGet(String directory, String file) {
        if (directory == null || directory.isEmpty()) {
            return Result.error(
                    TextError.of(
                            "Directory path is empty."
                    )
            );
        }

        if (file == null || file.isEmpty()) {
            return Result.error(
                    TextError.of(
                            "File name is empty."
                    )
            );
        }

        File dir = new File(directory);
        if (!dir.exists() || !dir.isDirectory()) {
            return Result.error(
                    TextError.of(
                            "Directory '%s' does not exist.",
                            directory
                    )
            );
        }
        File f = new File(directory, file);
        if (!f.exists()) {
            return Result.error(
                    TextError.of(
                            "File '%s' does not exist in directory '%s'.",
                            file,
                            directory
                    )
            );
        }
        return Result.success(f);
    }

    @NonNull
    public static Result<String, TextError> extractString(Supplier<String> supplier, String propertyName) {
        String value = supplier.get();
        if (value == null || value.isEmpty()) {
            return Result.error(
                    TextError.of(
                            "Missing value for '%s' property.",
                            propertyName
                    )
            );
        }
        return Result.success(value);
    }

    public static Result<Duration, TextError> extractDuration(Supplier<String> supplier,
                                                              String propertyName
    ) {
        return extractString(supplier, propertyName)
                .flatMap(value -> {
                    try {
                        return Result.success(Duration.parse(value));
                    } catch (Exception e) {
                        return Result.error(
                                TextError.of(
                                        "Invalid duration format for '%s' property. Expected ISO-8601 duration format.",
                                        propertyName
                                )
                        );
                    }
                });
    }
}
