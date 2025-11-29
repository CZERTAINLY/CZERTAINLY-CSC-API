package com.czertainly.csc.signing.configuration.profiles;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Supplier;

import static com.czertainly.csc.utils.assertions.ResultAssertions.assertErrorContains;
import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfigurationUtilsTest {

    @Test
    void extractStringReturnsValueIfPresent() {
        // given
        Supplier<String> stringSupplier = () -> "aString";

        // when
        var result = ConfigurationUtils.extractString(stringSupplier, "aProperty");

        // then
        String value = assertSuccessAndGet(result);
        assertEquals("aString", value);
    }

    @Test
    void extractStringReturnErrorIfEmpty() {
        // given
        Supplier<String> stringSupplier = () -> "";

        // when
        var result = ConfigurationUtils.extractString(stringSupplier, "aProperty");

        // then
        assertErrorContains(result, "Missing value for 'aProperty' property.");
    }

    @Test
    void extractStringReturnErrorIfNull() {
        // given
        Supplier<String> stringSupplier = () -> null;

        // when
        var result = ConfigurationUtils.extractString(stringSupplier, "aProperty");

        // then
        assertErrorContains(result, "Missing value for 'aProperty' property.");
    }

    @Test
    void extractDurationReturnsValueIfPresent() {
        // given
        Supplier<String> stringSupplier = () -> "PT1H";

        // when
        var result = ConfigurationUtils.extractDuration(stringSupplier, "aProperty");

        // then
        var duration = assertSuccessAndGet(result);
        assertEquals(3600, duration.getSeconds());
    }

    @Test
    void extractDurationReturnErrorIfInvalidFormat() {
        // given
        Supplier<String> stringSupplier = () -> "invalid";

        // when
        var result = ConfigurationUtils.extractDuration(stringSupplier, "aProperty");

        // then
        assertErrorContains(result,
                            "Invalid duration format for 'aProperty' property. Expected ISO-8601 duration format."
        );
    }

    @Test
    void extractDurationReturnErrorIfEmpty() {
        // given
        Supplier<String> stringSupplier = () -> "";

        // when
        var result = ConfigurationUtils.extractDuration(stringSupplier, "aProperty");

        // then
        assertErrorContains(result, "Missing value for 'aProperty' property.");
    }

    @Test
    void extractDurationReturnErrorIfNull() {
        // given
        Supplier<String> stringSupplier = () -> null;

        // when
        var result = ConfigurationUtils.extractDuration(stringSupplier, "aProperty");

        // then
        assertErrorContains(result, "Missing value for 'aProperty' property.");
    }

    @Test
    void checkFileExistenceAndGetReturnsFileIfPresent() throws IOException {
        // given
        Path directory = Files.createTempDirectory("tmpDir");
        Path file = Files.createTempFile(directory, "tmpFile", ".yml");


        // when
        var result = ConfigurationUtils.checkFileExistenceAndGet(directory.toString(), file.getFileName().toString());

        // then
        var f = assertSuccessAndGet(result);
        assertEquals(file.toFile(), f);
    }

    @Test
    void checkFileExistenceAndGetReturnsErrorIfDirectoryDoesNotExist() throws IOException {
        // given
        Path directory = Path.of("nonExistingDirectory");
        Path file = Files.createTempFile("tmpFile", ".yml");

        // when
        var result = ConfigurationUtils.checkFileExistenceAndGet(directory.toString(), file.getFileName().toString());

        // then
        assertErrorContains(result, "Directory 'nonExistingDirectory' does not exist.");
    }

    @Test
    void checkFileExistenceAndGetReturnsErrorIfDirectoryIsNotADirectory() throws IOException {
        // given
        Path directory = Files.createTempFile("tmpDir", ".yml");
        Path file = Files.createTempFile("tmpFile", ".yml");

        // when
        var result = ConfigurationUtils.checkFileExistenceAndGet(directory.toString(), file.getFileName().toString());

        // then
        assertErrorContains(result, "does not exist");
    }

    @Test
    void checkFileExistenceAndGetReturnsErrorIfFileDoesNotExist() throws IOException {
        // given
        Path directory = Files.createTempDirectory("tmpDir");
        Path file = Path.of(directory.toString(), "nonExistingFile.yml");

        // when
        var result = ConfigurationUtils.checkFileExistenceAndGet(directory.toString(), file.getFileName().toString());

        // then
        assertErrorContains(result, "File 'nonExistingFile.yml' does not exist in directory");
    }

    @Test
    void checkFileExistenceAndGetReturnsErrorIfFileIsEmpty() throws IOException {
        // given
        Path directory = Files.createTempDirectory("tmpDir");
        String file = "";

        // when
        var result = ConfigurationUtils.checkFileExistenceAndGet(directory.toString(), "");

        // then
        assertErrorContains(result, "File name is empty.");
    }

    @Test
    void checkFileExistenceAndGetReturnsErrorIfDirectoryIsEmpty() throws IOException {
        // given
        String directory = "";
        Path file = Files.createTempFile("tmpFile", ".yml");

        // when
        var result = ConfigurationUtils.checkFileExistenceAndGet("", file.getFileName().toString());

        // then
        assertErrorContains(result, "Directory path is empty.");
    }

    @Test
    void checkFileExistenceAndGetReturnErrorIfDirectoryIsNull() throws IOException {
        // given
        String directory = null;
        Path file = Files.createTempFile("tmpFile", ".yml");

        // when
        var result = ConfigurationUtils.checkFileExistenceAndGet(directory, file.getFileName().toString());

        // then
        assertErrorContains(result, "Directory path is empty.");
    }

    @Test
    void checkFileExistenceAndGetReturnErrorIfFileIsNull() throws IOException {
        // given
        Path directory = Files.createTempDirectory("tmpDir");
        String file = null;

        // when
        var result = ConfigurationUtils.checkFileExistenceAndGet(directory.toString(), file);

        // then
        assertErrorContains(result, "File name is empty.");
    }
}