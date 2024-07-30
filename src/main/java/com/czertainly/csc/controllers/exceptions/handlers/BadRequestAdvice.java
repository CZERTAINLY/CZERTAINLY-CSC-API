package com.czertainly.csc.controllers.exceptions.handlers;

import com.czertainly.csc.api.common.ErrorDto;
import com.czertainly.csc.controllers.exceptions.BadRequestException;
import com.czertainly.csc.controllers.exceptions.ServerErrorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class BadRequestAdvice {

    Logger logger = LoggerFactory.getLogger(BadRequestAdvice.class);

    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(BadRequestException.class)
    ErrorDto badRequest(BadRequestException ex) {
        return new ErrorDto(ex.getError(), ex.getErrorDescription());
    }

    @ResponseBody
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(ServerErrorException.class)
    ErrorDto unknownError(ServerErrorException ex) {
        logger.error("A Server Error Occurred", ex);
        return new ErrorDto(ex.getError(), ex.getErrorDescription());
    }
}
