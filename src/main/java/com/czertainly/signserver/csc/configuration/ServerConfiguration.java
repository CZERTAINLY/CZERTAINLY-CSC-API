package com.czertainly.signserver.csc.configuration;

import com.czertainly.signserver.csc.api.auth.authn.CscJwtAuthenticationConverter;
import com.czertainly.signserver.csc.clients.signserver.ws.SignserverWSClient;
import com.czertainly.signserver.csc.common.ApplicationConfigurationException;
import com.czertainly.signserver.csc.model.signserver.CryptoToken;
import com.czertainly.signserver.csc.signing.configuration.*;
import com.czertainly.signserver.csc.signing.filter.Worker;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
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

    @Bean
    public HttpComponentsMessageSender httpComponentsMessageSender(
            @Value("${signserver.clientKeyStore.storePassword}") String keystorePassword,
            @Value("${signserver.clientKeyStore.keyPassword}") String keyPassword,
            @Value("${signserver.clientKeyStore.storePath}") String keystorePath) throws ApplicationConfigurationException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream keyStoreInputStream = new FileInputStream(keystorePath)) {
                keyStore.load(keyStoreInputStream, keystorePassword.toCharArray());
            }

            SSLContext sslContext = SSLContexts.custom()
                                               .loadKeyMaterial(keyStore, keyPassword.toCharArray())
                                               .build();

            CloseableHttpClient httpClient = HttpClients.custom()
                                                        .setSSLContext(sslContext)
                                                        .addInterceptorFirst(new HttpComponentsMessageSender.RemoveSoapHeadersInterceptor())
                                                        .build();

            return new HttpComponentsMessageSender(httpClient);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                 UnrecoverableKeyException | KeyManagementException e) {
            throw new ApplicationConfigurationException("Failed to configure application." + e.getMessage());
        }
    }

    @Bean
    public Jaxb2Marshaller marshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPath("com.czertainly.signserver.csc.clients.signserver.ws.dto");
        return marshaller;
    }

    @Bean
    public SignserverWSClient signserverWSClient(Jaxb2Marshaller marshaller, HttpComponentsMessageSender httpComponentsMessageSender, @Value("${signserver.url}") String signserverUrl) {
        SignserverWSClient client = new SignserverWSClient(signserverUrl);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        client.setMessageSender(httpComponentsMessageSender);
        return client;
    }

    @Bean
    public WorkerRepository signerSelector() {
        CryptoToken entrustCryptoToken = new CryptoToken("EntrustSAMCryptoToken", 2);
        Worker XAdESBBWorker = new Worker("XAdES-Baseline-B", 1009, entrustCryptoToken);

        List<WorkerWithCapabilities> workersWithCapabilities = List.of(
                new WorkerWithCapabilities(XAdESBBWorker, new WorkerCapabilities(List.of("eu_eidas_qes", "eu_eidas_aes"), SignatureFormat.XAdES, ConformanceLevel.AdES_B_B))
        );

        return new WorkerRepository(workersWithCapabilities);
    }
}
