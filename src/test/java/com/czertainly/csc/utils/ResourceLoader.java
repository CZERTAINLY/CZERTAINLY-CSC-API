package com.czertainly.csc.utils;

import java.io.IOException;
import java.io.InputStream;

public class ResourceLoader {

    public static byte[] loadBytesFromResources(String resourcePath) throws IOException {
        try (InputStream inputStream = ResourceLoader.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }
            return inputStream.readAllBytes();
        }
    }

}
