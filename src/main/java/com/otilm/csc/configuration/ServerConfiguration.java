package com.otilm.csc.configuration;

import com.otilm.csc.api.auth.authn.CscJwtAuthenticationConverter;
import com.otilm.csc.clients.ejbca.ws.EjbcaWsClient;
import com.otilm.csc.clients.signserver.ws.SignserverWsClient;
import com.otilm.csc.common.exceptions.ApplicationConfigurationException;
import com.otilm.csc.configuration.idp.IdpAuthentication;
import com.otilm.csc.configuration.idp.IdpConfiguration;
import com.otilm.csc.signing.configuration.WorkerRepository;
import com.otilm.csc.signing.configuration.WorkerWithCapabilities;
import com.otilm.csc.signing.configuration.loader.WorkerConfigurationLoader;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.client5.http.ssl.HttpsSupport;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.annotation.Order;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.ws.transport.http.HttpComponents5ClientFactory;
import org.springframework.ws.transport.http.SimpleHttpComponents5MessageSender;

import javax.net.ssl.SSLContext;
import java.security.*;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@PropertySource(value = "file:${csc.profilesConfigurationDirectory}/key-pool-profiles.yml", factory = MultipleYamlPropertySourceFactory.class)
public class ServerConfiguration {

    private final HttpClientProperties httpClientProperties;

    public ServerConfiguration(HttpClientProperties httpClientProperties) {
        this.httpClientProperties = httpClientProperties;
    }

    @Bean
    @Order(1)
    SecurityFilterChain filterChain(HttpSecurity http) {
        http
                .sessionManagement(sessionConf -> sessionConf.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(
                        oauth2 -> {
                            oauth2.jwt(withDefaults());
                            oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(new CscJwtAuthenticationConverter()));
                        }
                );

        return http.build();
    }

    @Bean("signserverMessageSender")
    public SimpleHttpComponents5MessageSender signserverHttpComponentsMessageSender(
            @Value("${signingProvider.signserver.admin.keystoreBundle:none}") String keystoreBundleName,
            @Value("${signingProvider.signserver.truststoreBundle:none}") String truststoreBundleName,
            SslBundles sslBundles
    ) throws ApplicationConfigurationException {
        return getHttpComponentsMessageSender(keystoreBundleName, truststoreBundleName, sslBundles);
    }

    @Bean("ejbcaMessageSender")
    public SimpleHttpComponents5MessageSender ejbcaHttpComponentsMessageSender(
            @Value("${caProvider.ejbca.admin.keystoreBundle:none}") String keystoreBundleName,
            @Value("${caProvider.ejbca.truststoreBundle:none}") String truststoreBundleName,
            SslBundles sslBundles
    ) throws ApplicationConfigurationException {
        return getHttpComponentsMessageSender(keystoreBundleName, truststoreBundleName, sslBundles);
    }

    @Bean(name = "signserverWsMarshaller")
    public Jaxb2Marshaller signserverWsMarshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPath("com.otilm.csc.clients.signserver.ws.dto");
        return marshaller;
    }

    @Bean(name = "ejbcaWsMarshaller")
    public Jaxb2Marshaller ejbcaWsMarshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPath("com.otilm.csc.clients.ejbca.ws.dto");
        return marshaller;
    }

    @Bean("signserverRequestFactory")
    public HttpComponentsClientHttpRequestFactory signserverRequestFactory(
            @Value("${signingProvider.signserver.client.authType}") SignApiAuthorization authzType,
            @Value("${signingProvider.signserver.client.certificate.keystoreBundle:none}") String keystoreBundleName,
            @Value("${signingProvider.signserver.truststoreBundle:none}") String truststoreBundleName,
            SslBundles sslBundles
    ) throws ApplicationConfigurationException {
        try {
            SSLContextBuilder builder = SSLContexts.custom();

            if (!truststoreBundleName.equals("none") && !truststoreBundleName.isBlank()) {
                SslBundle truststoreBundle = sslBundles.getBundle(truststoreBundleName);
                KeyStore truststore = truststoreBundle.getStores().getTrustStore();
                builder.loadTrustMaterial(truststore, null);
            }

            if (authzType == SignApiAuthorization.CERTIFICATE) {
                if (keystoreBundleName.equals("none") || keystoreBundleName.isBlank()) {
                    throw new ApplicationConfigurationException(
                            "Keystore bundle name must be provided when using certificate authorization.");
                }
                SslStoreBundle keystoreBundle = sslBundles.getBundle(keystoreBundleName).getStores();
                KeyStore keystore = keystoreBundle.getKeyStore();
                builder.loadKeyMaterial(keystore, keystoreBundle.getKeyStorePassword().toCharArray());
            }

            SSLContext sslContext = builder.build();

            final HttpClient httpClient = getHttpClient(sslContext, null, httpClientProperties);

            return new HttpComponentsClientHttpRequestFactory(httpClient);
        } catch (Exception e) {
            throw new ApplicationConfigurationException("Failed to configure application." + e.getMessage());
        }
    }

    @Bean("idpClientRequestFactory")
    public HttpComponentsClientHttpRequestFactory idpRequestFactory(
            IdpConfiguration idpConfiguration,
            SslBundles sslBundles
    ) throws ApplicationConfigurationException {
        try {
            SSLContextBuilder builder = SSLContexts.custom();

            if (idpConfiguration.truststoreBundle() != null && !idpConfiguration.truststoreBundle().isBlank()) {
                SslBundle truststoreBundle = sslBundles.getBundle(idpConfiguration.truststoreBundle());
                KeyStore truststore = truststoreBundle.getStores().getTrustStore();
                builder.loadTrustMaterial(truststore, null);
            }

            if (idpConfiguration.client().authType() == IdpAuthentication.CERTIFICATE) {
                SslStoreBundle keystoreBundle = sslBundles.getBundle(
                        idpConfiguration.client().certificate().keystoreBundle()
                ).getStores();
                KeyStore keystore = keystoreBundle.getKeyStore();
                builder.loadKeyMaterial(keystore, keystoreBundle.getKeyStorePassword().toCharArray());
            }

            SSLContext sslContext = builder.build();

            final HttpClient httpClient = getHttpClient(sslContext, null, httpClientProperties);

            return new HttpComponentsClientHttpRequestFactory(httpClient);
        } catch (Exception e) {
            throw new ApplicationConfigurationException("Failed to configure application." + e.getMessage());
        }
    }

    @Bean
    public EjbcaWsClient ejbcaWsClient(@Qualifier("ejbcaWsMarshaller") Jaxb2Marshaller marshaller,
                                       @Qualifier("ejbcaMessageSender") SimpleHttpComponents5MessageSender httpComponentsMessageSender,
                                       @Value("${caProvider.ejbca.url}") String ejbcaUrl

    ) {
        EjbcaWsClient client = new EjbcaWsClient(ejbcaUrl);
        client.setMessageSender(httpComponentsMessageSender);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        return client;
    }

    @Bean
    public WorkerRepository signerSelector(WorkerConfigurationLoader workerConfigurationLoader) {
        List<WorkerWithCapabilities> workers = workerConfigurationLoader.getWorkers();

        return new WorkerRepository(workers);
    }

    @Bean
    public SignserverWsClient signserverWSClient(@Qualifier("signserverWsMarshaller") Jaxb2Marshaller marshaller,
                                                 @Qualifier("signserverMessageSender") SimpleHttpComponents5MessageSender httpComponentsMessageSender,
                                                 @Value("${signingProvider.signserver.url}") String signserverUrl
    ) {
        SignserverWsClient client = new SignserverWsClient(signserverUrl);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        client.setMessageSender(httpComponentsMessageSender);
        return client;
    }

    private SimpleHttpComponents5MessageSender getHttpComponentsMessageSender(
            String keystoreBundleName,
            String truststoreBundleName,
            SslBundles sslBundles
    ) {
        try {
            SSLContextBuilder builder = SSLContexts.custom();

            if (!truststoreBundleName.equals("none") && !truststoreBundleName.isBlank()) {
                SslBundle truststoreBundle = sslBundles.getBundle(truststoreBundleName);
                KeyStore truststore = truststoreBundle.getStores().getTrustStore();
                builder.loadTrustMaterial(truststore, null);
            }

            if (keystoreBundleName.equals("none") || keystoreBundleName.isBlank()) {
                throw new ApplicationConfigurationException(
                        "Keystore bundle name must be provided when using certificate authorization.");
            }
            SslStoreBundle keystoreBundle = sslBundles.getBundle(keystoreBundleName).getStores();
            KeyStore keystore = keystoreBundle.getKeyStore();
            builder.loadKeyMaterial(keystore, keystoreBundle.getKeyStorePassword().toCharArray());

            SSLContext sslContext = builder.build();

            final HttpClient httpClient = getHttpClient(sslContext,
                                                        new HttpComponents5ClientFactory.RemoveSoapHeadersInterceptor(),
                                                        httpClientProperties
            );

            return new SimpleHttpComponents5MessageSender(httpClient);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyManagementException e) {
            throw new ApplicationConfigurationException("Failed to configure application." + e.getMessage());
        }
    }

    private static HttpClient getHttpClient(SSLContext sslContext, HttpRequestInterceptor interceptor,
                                            HttpClientProperties properties
    ) {
        // Hostname verification and the TCP keep-alive options are stated explicitly rather than left
        // to the HttpClient defaults, which changed in httpclient5 5.6 / httpcore5 5.4: the
        // single-argument DefaultClientTlsStrategy constructor now selects
        // HostnameVerificationPolicy.BUILTIN (JSSE endpoint identification, which rejects
        // certificates carrying no subjectAltName), and SocketConfig changed its defaults from
        // soKeepAlive=false with tcpKeepIdle/Interval/Count=-1 to soKeepAlive=true with 5/5/3.
        // Outbound calls to EJBCA, SignServer and the IDP keep the previous semantics.
        TlsSocketStrategy tlsSocketStrategy = new DefaultClientTlsStrategy(sslContext,
                                                                          HostnameVerificationPolicy.CLIENT,
                                                                          HttpsSupport.getDefaultHostnameVerifier()
        );
        SocketConfig socketConfig = SocketConfig.custom()
                                                .setSoTimeout(properties.getReadTimeoutSeconds(), TimeUnit.SECONDS)
                                                .setSoKeepAlive(false)
                                                .setTcpKeepIdle(-1)
                                                .setTcpKeepInterval(-1)
                                                .setTcpKeepCount(-1)
                                                .build();
        final var connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                                                                               .setDefaultSocketConfig(socketConfig)
                                                                               .setTlsSocketStrategy(tlsSocketStrategy)
                                                                               .setMaxConnTotal(
                                                                                       properties.getMaxTotal())
                                                                               .setMaxConnPerRoute(
                                                                                       properties.getDefaultMaxPerRoute())
                                                                               .build();

        RequestConfig requestConfig = RequestConfig.custom()
                                                   .setConnectionRequestTimeout(Timeout.ofSeconds(
                                                           properties.getConnectionRequestTimeoutSeconds()))
                                                   .setResponseTimeout(
                                                           Timeout.ofSeconds(properties.getResponseTimeoutSeconds()))
                                                   .build();

        HttpClientBuilder builder = HttpClients.custom()
                                               .setConnectionManager(connectionManager)
                                               .setDefaultRequestConfig(requestConfig);

        if (interceptor != null) {
            builder.addRequestInterceptorFirst(interceptor);
        }

        return builder.build();
    }

    @Bean
    public ObjectMapper objectMapper() {
        return JsonMapper.builder()
                .changeDefaultPropertyInclusion(v -> JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL))
                .build();
    }
}
