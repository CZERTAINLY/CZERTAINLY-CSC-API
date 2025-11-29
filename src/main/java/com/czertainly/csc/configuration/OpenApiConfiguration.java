package com.czertainly.csc.configuration;

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import jakarta.annotation.PostConstruct;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

@Configuration
public class OpenApiConfiguration {

    private String appVersion;

    @PostConstruct
    public void init() throws IOException {
        Properties props = new Properties();
        props.load(new ClassPathResource("version.properties").getInputStream());
        appVersion = props.getProperty("app.version");
        System.out.println("App Version: " + appVersion);
    }

    public String getAppVersion() {
        return appVersion;
    }

    @Bean
    public GroupedOpenApi cscApis() {
        return GroupedOpenApi.builder()
                             .group("czertainly-csc-api")
                             .packagesToScan("com.czertainly.csc.controllers")
                             //.pathsToMatch("/v1/**")
                             .build();
    }

    @Bean
    public OpenAPI cscOpenAPI() {
        Map<String, Object> logoExtension = new HashMap<>();
        Map<String, Object> logoExtensionFields = new HashMap<>();
        logoExtensionFields.put("url",
                                "https://github.com/CZERTAINLY/CZERTAINLY/blob/develop/czertainly-logo/czertainly_color_H.svg"
        );
        logoExtension.put("x-logo", logoExtensionFields);

        return new OpenAPI()
                .info(new Info().title("CZERTAINLY CSC API")
                                .description("CZERTAINLY CSC API Documentation")
                                .version(getAppVersion())
                                .license(new License()
                                                 .name("MIT License")
                                                 .url("https://github.com/CZERTAINLY/CZERTAINLY/blob/develop/LICENSE.md"))
                                .extensions(logoExtension)
                                .contact(new Contact()
                                                 .name("CZERTAINLY")
                                                 .url("https://www.czertainly.com")
                                                 .email("info@czertainly.com")))
                .externalDocs(new ExternalDocumentation()
                                      .description("CZERTAINLY Documentation")
                                      .url("https://docs.czertainly.com"))
                .servers(List.of(new Server().url("https://csc.czertainly.online")))
                .schemaRequirement(
                        "BearerAuthSignature",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .description("""
                                                     Bearer authentication with `credential` or `service` scope. If the access token passed
                                                     in the `Authorization` HTTP header has scope `service`, the signing application MUST pass an
                                                     access token with scope `credential` in the `SAD` request parameter. This is not required,
                                                     if the the access token passed in the `Authorization` HTTP header has scope `credential`.
                                                     """)
                )
                .schemaRequirement(
                        "BearerAuthCredential",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .description("""
                                                     Bearer authentication with `credential` or `service` scope.
                                                     """)
                )
                .schemaRequirement(
                        "BearerAuthCredentialManagement",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .description("""
                                                     Bearer authentication with `manageCredentials` scope.
                                                     """)
                );
    }

}