package com.czertainly.csc.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for HTTP client connection pool and timeouts.
 */
@Component
@ConfigurationProperties(prefix = "http.client")
public class HttpClientProperties {

    /**
     * Maximum total connections in the connection pool.
     * Default: 200
     */
    private int maxTotal = 200;

    /**
     * Maximum connections per route.
     * Default: 20
     */
    private int defaultMaxPerRoute = 20;

    /**
     * Connection request timeout in seconds.
     * Time to wait for a connection from the connection pool.
     * Default: 10 seconds
     */
    private int connectionRequestTimeoutSeconds = 10;

    /**
     * Socket read timeout in seconds.
     * Time to wait for data after establishing connection.
     * Default: 30 seconds
     */
    private int readTimeoutSeconds = 30;

    /**
     * HTTP Response timeout in seconds.
     * Total time to wait for the complete response.
     * Default: 30 seconds
     */
    private int responseTimeoutSeconds = 30;

    public int getMaxTotal() {
        return maxTotal;
    }

    public void setMaxTotal(int maxTotal) {
        this.maxTotal = maxTotal;
    }

    public int getDefaultMaxPerRoute() {
        return defaultMaxPerRoute;
    }

    public void setDefaultMaxPerRoute(int defaultMaxPerRoute) {
        this.defaultMaxPerRoute = defaultMaxPerRoute;
    }

    public int getConnectionRequestTimeoutSeconds() {
        return connectionRequestTimeoutSeconds;
    }

    public void setConnectionRequestTimeoutSeconds(int connectionRequestTimeoutSeconds) {
        this.connectionRequestTimeoutSeconds = connectionRequestTimeoutSeconds;
    }

    public int getReadTimeoutSeconds() {
        return readTimeoutSeconds;
    }

    public void setReadTimeoutSeconds(int readTimeoutSeconds) {
        this.readTimeoutSeconds = readTimeoutSeconds;
    }

    public int getResponseTimeoutSeconds() {
        return responseTimeoutSeconds;
    }

    public void setResponseTimeoutSeconds(int responseTimeoutSeconds) {
        this.responseTimeoutSeconds = responseTimeoutSeconds;
    }
}
