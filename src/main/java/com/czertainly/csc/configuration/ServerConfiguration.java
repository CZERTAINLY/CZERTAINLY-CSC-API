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
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.ws.transport.http.HttpComponents5MessageSender;

import javax.net.ssl.SSLContext;
import java.security.*;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
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
    public HttpComponents5MessageSender signserverHttpComponentsMessageSender(
            @Value("${signingProvider.signserver.admin.keystoreBundle:none}") String keystoreBundleName,
            @Value("${signingProvider.signserver.truststoreBundle:none}") String truststoreBundleName,
            SslBundles sslBundles
    ) throws ApplicationConfigurationException {
        return getHttpComponentsMessageSender(keystoreBundleName, truststoreBundleName, sslBundles);
    }

    @Bean("ejbcaMessageSender")
    public HttpComponents5MessageSender ejbcaHttpComponentsMessageSender(
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

    private static HttpClient getHttpClient(SSLContext sslContext, HttpRequestInterceptor interceptor) {
        final var sslsf = new SSLConnectionSocketFactory(sslContext, new DefaultHostnameVerifier());

        final var socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                                                         .register("https", sslsf)
                                                         .build();

        final var connectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);

        HttpClientBuilder builder = HttpClients.custom()
                                               .setConnectionManager(connectionManager);

        if (interceptor != null) {
            builder.addRequestInterceptorFirst(interceptor);
        }

        return builder.build();
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
                                       @Qualifier("ejbcaMessageSender") HttpComponents5MessageSender httpComponentsMessageSender,
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

    private HttpComponents5MessageSender getHttpComponentsMessageSender(
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

           final HttpClient httpClient = getHttpClient(sslContext, new HttpComponents5MessageSender.RemoveSoapHeadersInterceptor());

            return new HttpComponents5MessageSender(httpClient);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyManagementException e) {
            throw new ApplicationConfigurationException("Failed to configure application." + e.getMessage());
        }
    }

    @Bean
    public SignserverWsClient signserverWSClient(@Qualifier("signserverWsMarshaller") Jaxb2Marshaller marshaller,
                                                 @Qualifier("signserverMessageSender") HttpComponents5MessageSender httpComponentsMessageSender,
                                                 @Value("${signingProvider.signserver.url}") String signserverUrl
    ) {
        SignserverWsClient client = new SignserverWsClient(signserverUrl);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        client.setMessageSender(httpComponentsMessageSender);
        return client;
    }

    @Bean
    public HttpClient getHttpClient(
            @Value("${signingProvider.signserver.truststoreBundle:none}") String truststoreBundleName,
            SslBundles sslBundles
    ) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        SSLContextBuilder builder = SSLContexts.custom();

        if (!truststoreBundleName.equals("none") && !truststoreBundleName.isBlank()) {
            SslBundle truststoreBundle = sslBundles.getBundle(truststoreBundleName);
            KeyStore truststore = truststoreBundle.getStores().getTrustStore();
            builder.loadTrustMaterial(truststore, null);
        }

        SSLContext sslContext = builder.build();

        final var sslsf = new SSLConnectionSocketFactory(sslContext, new DefaultHostnameVerifier());

        final var socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                                                         .register("https", sslsf)
                                                         .register("http", new PlainConnectionSocketFactory())
                                                         .build();

        final var connectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);

        HttpClientBuilder httpBuilder = HttpClients.custom()
                                                   .setConnectionManager(connectionManager);

        return httpBuilder.build();
    }
}
