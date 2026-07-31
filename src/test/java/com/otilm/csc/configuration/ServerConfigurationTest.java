package com.otilm.csc.configuration;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.util.Timeout;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Guards the outbound HTTP settings that {@link ServerConfiguration} states explicitly because the
 * underlying library defaults changed. These assertions are deliberately about exact values: if a
 * future httpclient5 or httpcore5 upgrade moves a default again, the configuration must keep
 * producing what EJBCA, SignServer and the IDP are reached with today, and these tests fail if the
 * explicit settings are dropped and the new defaults take over.
 */
class ServerConfigurationTest {

    @Test
    void outboundSocketConfigDisablesKeepAlive() {
        HttpClientProperties properties = new HttpClientProperties();
        properties.setReadTimeoutSeconds(30);

        SocketConfig socketConfig = ServerConfiguration.outboundSocketConfig(properties);

        // httpcore5 5.4 defaults these to true / 5 / 5 / 3.
        assertEquals(false, socketConfig.isSoKeepAlive());
        assertEquals(-1, socketConfig.getTcpKeepIdle());
        assertEquals(-1, socketConfig.getTcpKeepInterval());
        assertEquals(-1, socketConfig.getTcpKeepCount());
    }

    @Test
    void outboundSocketConfigAppliesConfiguredReadTimeout() {
        HttpClientProperties properties = new HttpClientProperties();
        properties.setReadTimeoutSeconds(45);

        SocketConfig socketConfig = ServerConfiguration.outboundSocketConfig(properties);

        assertEquals(Timeout.ofSeconds(45), socketConfig.getSoTimeout());
    }

    @Test
    void outboundTlsSocketStrategyVerifiesHostnamesWithTheHttpClientVerifier() throws Exception {
        SSLContext sslContext = defaultSslContext();

        Object strategy = ServerConfiguration.outboundTlsSocketStrategy(sslContext);

        // httpclient5 5.6 would otherwise select BUILTIN with no verifier, switching to JSSE endpoint
        // identification. Neither value is reachable through a public accessor, hence the reflection.
        assertEquals(HostnameVerificationPolicy.CLIENT, readField(strategy, "hostnameVerificationPolicy"));
        Object verifier = readField(strategy, "hostnameVerifier");
        assertNotNull(verifier, "a hostname verifier must be set, otherwise JSSE verification takes over");
        assertInstanceOf(DefaultHostnameVerifier.class, verifier);
        assertInstanceOf(HostnameVerifier.class, verifier);
    }

    @Test
    void getHttpClientBuildsAClientWithAnInterceptor() throws Exception {
        HttpClientProperties properties = new HttpClientProperties();
        HttpRequestInterceptor interceptor = (request, entity, context) -> {
            // no-op: this test only needs the interceptor branch to be taken
        };

        HttpClient client = ServerConfiguration.getHttpClient(defaultSslContext(), interceptor, properties);

        assertNotNull(client);
        assertInstanceOf(CloseableHttpClient.class, client);
        ((CloseableHttpClient) client).close();
    }

    @Test
    void getHttpClientBuildsAClientWithoutAnInterceptor() throws Exception {
        HttpClientProperties properties = new HttpClientProperties();

        HttpClient client = ServerConfiguration.getHttpClient(defaultSslContext(), null, properties);

        assertNotNull(client);
        assertInstanceOf(CloseableHttpClient.class, client);
        ((CloseableHttpClient) client).close();
    }

    private static SSLContext defaultSslContext() throws NoSuchAlgorithmException {
        return SSLContext.getDefault();
    }

    private static Object readField(Object target, String name) throws IllegalAccessException {
        for (Class<?> type = target.getClass(); type != null; type = type.getSuperclass()) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(target);
            } catch (NoSuchFieldException ignored) {
                // declared further up the hierarchy
            }
        }
        throw new AssertionError("field '" + name + "' not found on " + target.getClass());
    }
}
