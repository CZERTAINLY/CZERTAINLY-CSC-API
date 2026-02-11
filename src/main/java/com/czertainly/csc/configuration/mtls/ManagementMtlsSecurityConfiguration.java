package com.czertainly.csc.configuration.mtls;

import com.czertainly.csc.api.auth.authn.CscJwtAuthenticationConverter;
import com.czertainly.csc.common.exceptions.ApplicationConfigurationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.*;

@Configuration
@ConditionalOnExpression("'${csc.management.auth.type:oauth2}' == 'certificate' || '${csc.management.auth.type:oauth2}' == 'certificate_oauth2'")
@EnableConfigurationProperties({ManagementAuthConfiguration.class, ManagementMtlsProperties.class})
public class ManagementMtlsSecurityConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(ManagementMtlsSecurityConfiguration.class);

    private final ManagementMtlsProperties mtlsProps;
    private final ManagementAuthType authType;
    private final ObjectMapper objectMapper;
    private final SslBundles sslBundles;

    public ManagementMtlsSecurityConfiguration(
            ManagementAuthConfiguration authConfig,
            ObjectMapper objectMapper,
            SslBundles sslBundles
    ) {
        this.mtlsProps = authConfig.certificate();
        this.authType = authConfig.type();
        this.objectMapper = objectMapper;
        this.sslBundles = sslBundles;

        validateAtLeastOneCheckConfigured();
        logActiveChecks();
    }

    @Bean
    @Order(0)
    SecurityFilterChain managementMtlsFilterChain(HttpSecurity http) throws Exception {
        Set<TrustAnchor> trustAnchors = loadTrustAnchors();
        List<X500Name> allowedIssuers = parseX500Names(mtlsProps.allowedIssuers());
        List<X500Name> allowedSubjects = parseX500Names(mtlsProps.allowedSubjects());
        List<String> allowedFingerprints = mtlsProps.allowedFingerprints();
        boolean fallbackToOAuth2 = authType == ManagementAuthType.CERTIFICATE_OAUTH2;

        http
                .securityMatcher("management/v1/credentials/**")
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .addFilterBefore(
                        new MtlsClientCertificateFilter(objectMapper, fallbackToOAuth2, mtlsProps.clientCertificateHeader()),
                        BasicAuthenticationFilter.class)
                .addFilterAfter(
                        new MtlsAuthorizationFilter(objectMapper, trustAnchors,
                                allowedIssuers, allowedSubjects, allowedFingerprints),
                        MtlsClientCertificateFilter.class)
                .addFilterAfter(
                        new MtlsAuthenticationFilter(),
                        MtlsAuthorizationFilter.class);

        if (fallbackToOAuth2) {
            http
                    .sessionManagement(sessionConf -> sessionConf.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .csrf(AbstractHttpConfigurer::disable)
                    .oauth2ResourceServer(oauth2 ->
                            oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(new CscJwtAuthenticationConverter())));
        }

        return http.build();
    }

    private Set<TrustAnchor> loadTrustAnchors() {
        if (mtlsProps.truststoreBundle() == null || mtlsProps.truststoreBundle().isBlank()) {
            return Set.of();   // no truststore configured — skip PKIX re-validation
        }

        try {
            KeyStore truststore = sslBundles
                    .getBundle(mtlsProps.truststoreBundle())
                    .getStores()
                    .getTrustStore();

            Set<TrustAnchor> anchors = new HashSet<>();
            Enumeration<String> aliases = truststore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (truststore.isCertificateEntry(alias)) {
                    X509Certificate cert = (X509Certificate) truststore.getCertificate(alias);
                    anchors.add(new TrustAnchor(cert, null));
                }
            }

            if (anchors.isEmpty()) {
                throw new ApplicationConfigurationException(
                        "Management mTLS truststoreBundle '%s' contains no certificate entries."
                                .formatted(mtlsProps.truststoreBundle()));
            }

            logger.info("Management mTLS: loaded {} trust anchor(s) from bundle '{}'",
                    anchors.size(), mtlsProps.truststoreBundle());
            return anchors;

        } catch (Exception e) {
            throw new ApplicationConfigurationException(
                    "Failed to load management mTLS truststore bundle '%s': %s"
                            .formatted(mtlsProps.truststoreBundle(), e.getMessage()), e);
        }
    }

    private static List<X500Name> parseX500Names(List<String> dnStrings) {
        if (dnStrings.isEmpty()) {
            return List.of();
        }
        return dnStrings.stream()
                .map(dn -> {
                    try {
                        return new X500Name(dn);
                    } catch (IllegalArgumentException e) {
                        throw new ApplicationConfigurationException(
                                "Invalid DN string '%s' in mTLS configuration: %s. Expected format like 'CN=Name,O=Org,C=US'"
                                        .formatted(dn, e.getMessage()), e);
                    }
                })
                .toList();
    }

    private void validateAtLeastOneCheckConfigured() {
        boolean hasTruststore = mtlsProps.truststoreBundle() != null && !mtlsProps.truststoreBundle().isBlank();
        boolean hasIssuers = !mtlsProps.allowedIssuers().isEmpty();
        boolean hasSubjects = !mtlsProps.allowedSubjects().isEmpty();
        boolean hasFingerprints = !mtlsProps.allowedFingerprints().isEmpty();

        if (!hasTruststore && !hasIssuers && !hasSubjects && !hasFingerprints) {
            throw new ApplicationConfigurationException(
                    "Management mTLS is enabled (csc.management.auth.type=%s) but no "
                            .formatted(authType.name().toLowerCase())
                            + "authorization checks are configured. At least one of "
                            + "truststoreBundle, allowedIssuers, allowedSubjects, or "
                            + "allowedFingerprints must be set. "
                            + "Refusing to start to prevent accidental open access.");
        }
    }

    private void logActiveChecks() {
        List<String> active = new ArrayList<>();
        if (mtlsProps.truststoreBundle() != null && !mtlsProps.truststoreBundle().isBlank()) {
            active.add("truststoreBundle=" + mtlsProps.truststoreBundle());
        }
        if (!mtlsProps.allowedIssuers().isEmpty()) {
            active.add("allowedIssuers=" + mtlsProps.allowedIssuers());
        }
        if (!mtlsProps.allowedSubjects().isEmpty()) {
            active.add("allowedSubjects=" + mtlsProps.allowedSubjects());
        }
        if (!mtlsProps.allowedFingerprints().isEmpty()) {
            active.add("allowedFingerprints=" + mtlsProps.allowedFingerprints());
        }
        if (mtlsProps.clientCertificateHeader() != null && !mtlsProps.clientCertificateHeader().isBlank()) {
            active.add("clientCertificateHeader=" + mtlsProps.clientCertificateHeader());
        }
        logger.info("Management auth type: {}. Active mTLS authorization checks: {}",
                authType, String.join(",\n ", active));
    }
}
