package com.czertainly.csc.utils;

import org.springframework.validation.Errors;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.testcontainers.shaded.org.apache.commons.lang3.NotImplementedException;

import java.util.ArrayList;
import java.util.List;

public class TestValidationErrors implements Errors {

    List<FieldError> errors = new ArrayList<>();

    @Override
    public String getObjectName() {
        return "";
    }

    @Override
    public void reject(String errorCode, Object[] errorArgs, String defaultMessage) {
        throw new NotImplementedException();
    }

    @Override
    public void rejectValue(String field, String errorCode, Object[] errorArgs, String defaultMessage) {
        errors.add(new FieldError("", field, null, false, new String[]{errorCode}, errorArgs, defaultMessage));

    }

    @Override
    public List<ObjectError> getGlobalErrors() {
        return List.of();
    }

    @Override
    public List<FieldError> getFieldErrors() {
        return errors;
    }

    @Override
    public Object getFieldValue(String field) {
        return null;
    }

}
