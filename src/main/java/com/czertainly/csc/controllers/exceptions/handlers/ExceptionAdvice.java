package com.czertainly.csc.controllers.exceptions.handlers;

import com.czertainly.csc.api.common.ErrorDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.controllers.exceptions.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;


@ControllerAdvice
public class ExceptionAdvice {

    Logger logger = LoggerFactory.getLogger(ExceptionAdvice.class);

    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(BadRequestException.class)
    ErrorDto badRequest(BadRequestException ex) {
        return new ErrorDto("bad_request", ex.getMessage());
    }

    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(InvalidInputDataException.class)
    ErrorDto badRequest(InvalidInputDataException ex) {
        return new ErrorDto("invalid_request ", ex.getMessage());
    }

    @ResponseBody
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(InternalErrorException.class)
    ErrorDto internalError(InternalErrorException ex) {
        return new ErrorDto("internal_server_error", ex.getMessage());
    }

    @ResponseBody
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(ServiceUnavailableException.class)
    ErrorDto serviceUnavailable(InternalErrorException ex) {
        return new ErrorDto("service_unavailable", ex.getMessage());
    }

    @ResponseBody
    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ExceptionHandler(ForbiddenException.class)
    ErrorDto forbidden(ForbiddenException ex) {
        return new ErrorDto("forbidden", ex.getMessage());
    }

    @ResponseBody
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(UnauthorizedException.class)
    ErrorDto unauthorized(UnauthorizedException ex) {
        return new ErrorDto("unauthorized", ex.getMessage());
    }

    @ResponseBody
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(AccessDeniedException.class)
    ErrorDto unauthorized(AccessDeniedException ex) {
        return new ErrorDto("access_denied", ex.getMessage());
    }

    @ResponseBody
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(Exception.class)
    ErrorDto unauthorized(Exception ex) {
        logger.error("An unexpected error occurred.", ex);
        return new ErrorDto("unexpected_error", ex.getMessage());
    }
}
