package com.czertainly.signserver.csc.configuration;

import com.czertainly.signserver.csc.api.auth.authn.CscJwtAuthenticationConverter;
import com.czertainly.signserver.csc.clients.ejbca.ws.EjbcaWsClient;
import com.czertainly.signserver.csc.clients.signserver.ws.SignserverWsClient;
import com.czertainly.signserver.csc.common.PatternReplacer;
import com.czertainly.signserver.csc.common.exceptions.ApplicationConfigurationException;
import com.czertainly.signserver.csc.signing.configuration.WorkerRepository;
import com.czertainly.signserver.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.signserver.csc.signing.configuration.loader.WorkerConfigurationLoader;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
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
            @Value("${signingProvider.signserver.clientKeyStore.storePath}") String keystorePath,
            @Value("${signingProvider.signserver.clientKeyStore.password}") String password
    ) throws ApplicationConfigurationException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream keyStoreInputStream = new FileInputStream(keystorePath)) {
                keyStore.load(keyStoreInputStream, password.toCharArray());
            }

            SSLContext sslContext = SSLContexts.custom()
                                               .loadKeyMaterial(keyStore, password.toCharArray())
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

    @Bean("ejbcaMessageSender")
    public HttpComponents5MessageSender ejbcaHttpComponentsMessageSender(
            @Value("${caProvider.ejbca.clientKeyStore.storePath}") String keystorePath,
            @Value("${caProvider.ejbca.clientKeyStore.password}") String password
    ) throws ApplicationConfigurationException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream keyStoreInputStream = new FileInputStream(keystorePath)) {
                keyStore.load(keyStoreInputStream, password.toCharArray());
            }

            SSLContext sslContext = SSLContexts.custom()
                                               .loadKeyMaterial(keyStore, password.toCharArray())
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
                                                 @Value("${signingProvider.signserver.url}") String signserverUrl
    ) {
        SignserverWsClient client = new SignserverWsClient(signserverUrl);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        client.setMessageSender(httpComponentsMessageSender);
        return client;
    }

    @Bean
    public HttpComponentsClientHttpRequestFactory requestFactory(
            @Value("${signingProvider.signserver.authorization.type}") SignApiAuthorization authzType,
            @Value("${signingProvider.signserver.clientKeyStore.storePath}") String storePath,
            @Value("${signingProvider.signserver.clientKeyStore.password}") String password
    ) throws ApplicationConfigurationException {
        if (authzType != SignApiAuthorization.CERTIFICATE) {
            return new HttpComponentsClientHttpRequestFactory(HttpClients.createDefault());
        }

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream keyStoreInputStream = new FileInputStream(storePath)) {
                keyStore.load(keyStoreInputStream, password.toCharArray());
            }

            SSLContext sslContext = SSLContexts.custom()
                                               .loadKeyMaterial(keyStore, password.toCharArray())
                                               .build();


            final var sslsf = new SSLConnectionSocketFactory(sslContext, new DefaultHostnameVerifier());

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
                                       @Value("${caProvider.ejbca.url}") String ejbcaUrl,
                                       @Value("${caProvider.ejbca.ca}") String caName,
                                       @Value("${caProvider.ejbca.endEntityProfile}") String endEntityProfileName,
                                       @Value("${caProvider.ejbca.certificateProfile}") String certificateProfileName
    ) {
        EjbcaWsClient client = new EjbcaWsClient(ejbcaUrl, caName, endEntityProfileName, certificateProfileName);
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

    @Bean("dnProvider")
    public PatternReplacer usernameProvider(@Value("${caProvider.ejbca.dnPattern}") String dnPattern) {
        return new PatternReplacer(dnPattern, "Distinguished Name Provider");
    }
}
