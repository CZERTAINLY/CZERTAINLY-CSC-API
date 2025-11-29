package com.czertainly.csc.configuration.idp;

import com.czertainly.csc.configuration.validations.Url;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DurationUnit;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@Validated
@ConfigurationProperties(prefix = "idp")
public record IdpConfiguration(
        @Url String baseUrl,
        @Url String jwksUri,
        @Url(required = false) String userInfoUrl,
        @NotBlank String issuer,
        @NotBlank String audience,
        @NotNull @DurationUnit(ChronoUnit.SECONDS) Duration clockSkewSeconds,
        String truststoreBundle,
        @NotNull IdpClientAuth client
) implements Validator {

    @Override
    public boolean supports(Class<?> clazz) {
        return IdpConfiguration.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        IdpConfiguration conf = (IdpConfiguration) target;
        validateClientAuthentication(errors, conf.client());
    }

    private static void validateClientAuthentication(Errors errors, IdpClientAuth client) {
        if (client.authType() == IdpAuthentication.CERTIFICATE) {
            if (client.certificate() == null) {
                errors.rejectValue("client.certificate", "certificate.required",
                                   "Certificate is required if client.authType is CERTIFICATE."
                );
            } else {
                if (client.certificate().keystoreBundle() == null || client.certificate().keystoreBundle().isEmpty()) {
                    errors.rejectValue("client.keystoreBundle", "keystoreBundle.required",
                                       "Keystore bundle must be provided when client.authType is CERTIFICATE."
                    );
                }
            }
        }
    }
}
