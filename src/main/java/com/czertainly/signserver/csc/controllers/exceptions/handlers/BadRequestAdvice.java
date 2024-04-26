package com.czertainly.signserver.csc.controllers.exceptions.handlers;

import com.czertainly.signserver.csc.controllers.exceptions.BadRequestException;
import com.czertainly.signserver.csc.api.common.ErrorDto;
import com.czertainly.signserver.csc.controllers.exceptions.ServerErrorException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class BadRequestAdvice {

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
        return new ErrorDto(ex.getError(), ex.getErrorDescription());
    }
}
