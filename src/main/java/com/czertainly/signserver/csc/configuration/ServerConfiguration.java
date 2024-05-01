package com.czertainly.signserver.csc.configuration;

import com.czertainly.signserver.csc.api.auth.authn.CscJwtAuthenticationConverter;
import com.czertainly.signserver.csc.clients.ejbca.ws.EjbcaWsClient;
import com.czertainly.signserver.csc.clients.signserver.ws.SignserverWsClient;
import com.czertainly.signserver.csc.common.ApplicationConfigurationException;
import com.czertainly.signserver.csc.model.signserver.CryptoToken;
import com.czertainly.signserver.csc.signing.configuration.*;
import com.czertainly.signserver.csc.signing.filter.Worker;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.ws.transport.http.HttpComponents5MessageSender;
import org.springframework.ws.transport.http.HttpComponentsMessageSender;

import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
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
            @Value("${signserver.clientKeyStore.storePassword}") String keystorePassword,
            @Value("${signserver.clientKeyStore.keyPassword}") String keyPassword,
            @Value("${signserver.clientKeyStore.storePath}") String keystorePath
    ) throws ApplicationConfigurationException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream keyStoreInputStream = new FileInputStream(keystorePath)) {
                keyStore.load(keyStoreInputStream, keystorePassword.toCharArray());
            }

            SSLContext sslContext = SSLContexts.custom()
                                               .loadKeyMaterial(keyStore, keyPassword.toCharArray())
                                               .build();


            final var sslsf = new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());

            final var socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                                                             .register("https", sslsf)
                                                             .build();


            final var connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);

            final HttpClient httpClient = HttpClients.custom()
                                                     .setConnectionManager(connectionManager)
                                                     .addRequestInterceptorFirst(
                                                             new HttpComponents5MessageSender.RemoveSoapHeadersInterceptor())
                                                     .build();

            return new HttpComponents5MessageSender(httpClient);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                 UnrecoverableKeyException | KeyManagementException e) {
            throw new ApplicationConfigurationException("Failed to configure application." + e.getMessage());
        }
    }

    @Bean("ejbcaMessageSender")
    public HttpComponents5MessageSender ejbcaHttpComponentsMessageSender(
            @Value("${ejbca.clientKeyStore.storePassword}") String keystorePassword,
            @Value("${ejbca.clientKeyStore.keyPassword}") String keyPassword,
            @Value("${ejbca.clientKeyStore.storePath}") String keystorePath
    ) throws ApplicationConfigurationException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream keyStoreInputStream = new FileInputStream(keystorePath)) {
                keyStore.load(keyStoreInputStream, keystorePassword.toCharArray());
            }

            SSLContext sslContext = SSLContexts.custom()
                                               .loadKeyMaterial(keyStore, keyPassword.toCharArray())
                                               .build();


            final var sslsf = new SSLConnectionSocketFactory(sslContext, new DefaultHostnameVerifier());

            final var socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                                                             .register("https", sslsf)
                                                             .build();


            final var connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);

            final HttpClient httpClient = HttpClients.custom()
                                                     .setConnectionManager(connectionManager)
                                                     .addRequestInterceptorFirst(
                                                             new HttpComponents5MessageSender.RemoveSoapHeadersInterceptor())
                                                     .build();

            return new HttpComponents5MessageSender(httpClient);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                 UnrecoverableKeyException | KeyManagementException e) {
            throw new ApplicationConfigurationException("Failed to configure application." + e.getMessage());
        }
    }

    @Bean(name = "signserverWsMarshaller")
    public Jaxb2Marshaller signserverWsMarshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPath("com.czertainly.signserver.csc.clients.signserver.ws.dto");
        return marshaller;
    }

    @Bean(name = "ejbcaWsMarshaller")
    public Jaxb2Marshaller ejbcaWsMarshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPath("com.czertainly.signserver.csc.clients.ejbca.ws.dto");
        return marshaller;
    }

    @Bean
    public SignserverWsClient signserverWSClient(@Qualifier("signserverWsMarshaller") Jaxb2Marshaller marshaller,
                                                 @Qualifier("signserverMessageSender") HttpComponents5MessageSender httpComponentsMessageSender,
                                                 @Value("${signserver.url}") String signserverUrl
    ) {
        SignserverWsClient client = new SignserverWsClient(signserverUrl);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        client.setMessageSender(httpComponentsMessageSender);
        return client;
    }

    @Bean
    public HttpComponentsClientHttpRequestFactory requestFactory(
            @Value("${signserver.clientKeyStore.storePassword}") String keystorePassword,
            @Value("${signserver.clientKeyStore.keyPassword}") String keyPassword,
            @Value("${signserver.clientKeyStore.storePath}") String keystorePath
    ) throws ApplicationConfigurationException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream keyStoreInputStream = new FileInputStream(keystorePath)) {
                keyStore.load(keyStoreInputStream, keystorePassword.toCharArray());
            }

            SSLContext sslContext = SSLContexts.custom()
                                               .loadKeyMaterial(keyStore, keyPassword.toCharArray())
                                               .build();


            final var sslsf = new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());

            final var socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                                                             .register("https", sslsf)
                                                             .build();


            final var connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);

            final HttpClient httpClient = HttpClients.custom()
                                                     .setConnectionManager(connectionManager)
                                                     .build();

            return new HttpComponentsClientHttpRequestFactory(httpClient);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                 UnrecoverableKeyException | KeyManagementException e) {
            throw new ApplicationConfigurationException("Failed to configure application." + e.getMessage());
        }
    }

    @Bean
    public EjbcaWsClient ejbcaWsClient(@Qualifier("ejbcaWsMarshaller") Jaxb2Marshaller marshaller,
                                       @Qualifier("ejbcaMessageSender") HttpComponents5MessageSender httpComponentsMessageSender,
                                       @Value("${ejbca.url}") String ejbcaUrl
    ) {
        EjbcaWsClient client = new EjbcaWsClient(ejbcaUrl, "DemoClientSubCA_2307RSA",
                                                 "DemoDocumentSigningEndEntityProfile",
                                                 "DemoDocumentSigningLongEECertificateProfile"
        );
        client.setMessageSender(httpComponentsMessageSender);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        return client;
    }

    @Bean
    public WorkerRepository signerSelector() {
        CryptoToken entrustCryptoToken = new CryptoToken("EntrustSAMCryptoToken", 10);
        Worker XAdESBBWorker = new Worker("XAdES-Baseline-B", 1009, entrustCryptoToken);

        List<WorkerWithCapabilities> workersWithCapabilities = List.of(
                new WorkerWithCapabilities(XAdESBBWorker,
                                           new WorkerCapabilities(List.of("eu_eidas_qes", "eu_eidas_aes"),
                                                                  SignatureFormat.XAdES, ConformanceLevel.AdES_B_B,
                                                                  SignaturePackaging.DETACHED
                                           )
                )
        );

        return new WorkerRepository(workersWithCapabilities);
    }
}
