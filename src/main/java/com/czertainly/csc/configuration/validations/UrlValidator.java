package com.czertainly.csc.configuration.validations;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.net.URI;

public class UrlValidator implements ConstraintValidator<Url, String> {

    private boolean required = true;

    @Override
    public void initialize(Url constraintAnnotation) {
        ConstraintValidator.super.initialize(constraintAnnotation);
        required = constraintAnnotation.required();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {

        if (!required && (value == null)) {
            return true;
        }

        try {
            new URI(value).toURL();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
