package com.czertainly.csc.configuration;

import com.czertainly.csc.api.auth.authn.CscJwtAuthenticationConverter;
import com.czertainly.csc.clients.ejbca.ws.EjbcaWsClient;
import com.czertainly.csc.clients.signserver.ws.SignserverWsClient;
import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.csc.configuration.idp.IdpAuthentication;
import com.czertainly.csc.configuration.idp.IdpConfiguration;
import com.czertainly.csc.signing.configuration.WorkerRepository;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.loader.WorkerConfigurationLoader;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.ws.transport.http.HttpComponents5ClientFactory;
import org.springframework.ws.transport.http.HttpComponents5MessageSender;
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

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
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
        marshaller.setContextPath("com.czertainly.csc.clients.signserver.ws.dto");
        return marshaller;
    }

    @Bean(name = "ejbcaWsMarshaller")
    public Jaxb2Marshaller ejbcaWsMarshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPath("com.czertainly.csc.clients.ejbca.ws.dto");
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

            final HttpClient httpClient = getHttpClient(sslContext, null);

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

            final HttpClient httpClient = getHttpClient(sslContext, null);

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

           final HttpClient httpClient = getHttpClient(sslContext, new HttpComponents5ClientFactory.RemoveSoapHeadersInterceptor());

            return new SimpleHttpComponents5MessageSender(httpClient);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyManagementException e) {
            throw new ApplicationConfigurationException("Failed to configure application." + e.getMessage());
        }
    }

    private static HttpClient getHttpClient(SSLContext sslContext, HttpRequestInterceptor interceptor) {
        TlsSocketStrategy tlsSocketStrategy = new DefaultClientTlsStrategy(sslContext);
        SocketConfig socketConfig = SocketConfig.custom().setSoTimeout(10, TimeUnit.SECONDS).build();
        final var connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                                                                               .setDefaultSocketConfig(socketConfig)
                                                                               .setTlsSocketStrategy(tlsSocketStrategy)
                                                                               .build();

        HttpClientBuilder builder = HttpClients.custom().setConnectionManager(connectionManager);

        if (interceptor != null) {
            builder.addRequestInterceptorFirst(interceptor);
        }

        return builder.build();
    }
}
