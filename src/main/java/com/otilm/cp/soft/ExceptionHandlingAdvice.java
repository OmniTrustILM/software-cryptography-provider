package com.otilm.cp.soft;

import com.otilm.api.exception.*;
import com.otilm.cp.soft.dto.ApiErrorResponseDto;
import com.otilm.cp.soft.dto.ErrorMessageDto;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@RestControllerAdvice
public class ExceptionHandlingAdvice {

    private static final Logger log = LoggerFactory.getLogger(ExceptionHandlingAdvice.class);

    private static final String ARGUMENTS_NOT_VALID = "Arguments not valid";

    @ExceptionHandler({ MethodArgumentNotValidException.class })
    protected ResponseEntity<Object> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        List<ErrorMessageDto> errors = new ArrayList<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            ErrorMessageDto errorMessage = new ErrorMessageDto(error.getField(), ex.getClass().getSimpleName(), error.getDefaultMessage());
            if (log.isDebugEnabled()) {
                errorMessage.setStacktrace(ExceptionUtils.getStackTrace(ex));
            }
            errors.add(errorMessage);
        }
        for (ObjectError error : ex.getBindingResult().getGlobalErrors()) {
            ErrorMessageDto errorMessage = new ErrorMessageDto(error.getObjectName(), ex.getClass().getSimpleName(), error.getDefaultMessage());
            if (log.isDebugEnabled()) {
                errorMessage.setStacktrace(ExceptionUtils.getStackTrace(ex));
            }
            errors.add(errorMessage);
        }
        ApiErrorResponseDto apiErrorResponseDto = new ApiErrorResponseDto(80, HttpStatus.BAD_REQUEST, ARGUMENTS_NOT_VALID, errors);
        return new ResponseEntity<>(
                apiErrorResponseDto, new HttpHeaders(), apiErrorResponseDto.getStatus());
    }

    @ExceptionHandler({ MethodArgumentTypeMismatchException.class })
    public ResponseEntity<Object> handleMethodArgumentTypeMismatchException(MethodArgumentTypeMismatchException ex) {
        ErrorMessageDto errorMessage = new ErrorMessageDto(ex.getName(), ex.getClass().getSimpleName(), ex.getValue().toString());
        if (log.isDebugEnabled()) {
            errorMessage.setStacktrace(ExceptionUtils.getStackTrace(ex));
        }
        ApiErrorResponseDto apiErrorResponseDto = new ApiErrorResponseDto(81, HttpStatus.BAD_REQUEST, ARGUMENTS_NOT_VALID, errorMessage);
        apiErrorResponseDto.setTimestamp(Instant.now().toEpochMilli());
        log.error("{}", apiErrorResponseDto.getMessage(), ex);
        return new ResponseEntity<>(
                apiErrorResponseDto, new HttpHeaders(), apiErrorResponseDto.getStatus());
    }

    @ExceptionHandler({ HttpMessageNotReadableException.class })
    public ResponseEntity<Object> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
        ErrorMessageDto errorMessage;
        final Throwable cause = ex.getCause();
        if (cause instanceof InvalidFormatException) {
            InvalidFormatException exCause = (InvalidFormatException) ex.getCause();
            errorMessage = new ErrorMessageDto(exCause.getPath().get(0).getFieldName(), exCause.getClass().getSimpleName(), exCause.getValue().toString());
            if (log.isDebugEnabled()) {
                errorMessage.setStacktrace(ExceptionUtils.getStackTrace(exCause));
            }
        } else {
            errorMessage = new ErrorMessageDto(ex.getRootCause().getMessage(), ex.getClass().getSimpleName(), ex.getMessage());
            if (log.isDebugEnabled()) {
                errorMessage.setStacktrace(ExceptionUtils.getStackTrace(ex));
            }
        }
        ApiErrorResponseDto apiErrorResponseDto = new ApiErrorResponseDto(81, HttpStatus.BAD_REQUEST, ARGUMENTS_NOT_VALID, errorMessage);
        apiErrorResponseDto.setTimestamp(Instant.now().toEpochMilli());
        log.error("{}", apiErrorResponseDto.getMessage(), ex);
        return new ResponseEntity<>(
                apiErrorResponseDto, new HttpHeaders(), apiErrorResponseDto.getStatus());
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<Object> handleNotFoundException(NotFoundException ex) {
        ErrorMessageDto errorMessage = new ErrorMessageDto(ex.getMessage(), ex.getClass().getSimpleName(), null);
        if (log.isDebugEnabled()) {
            errorMessage.setStacktrace(ExceptionUtils.getStackTrace(ex));
        }
        ApiErrorResponseDto apiErrorResponseDto = new ApiErrorResponseDto(404, HttpStatus.NOT_FOUND, "Object not found", errorMessage);
        apiErrorResponseDto.setTimestamp(Instant.now().toEpochMilli());
        log.error("{}", apiErrorResponseDto.getMessage(), ex);
        return new ResponseEntity<>(
                apiErrorResponseDto, new HttpHeaders(), apiErrorResponseDto.getStatus());
    }

    @ExceptionHandler(AlreadyExistException.class)
    public ResponseEntity<Object> handleAlreadyExistException(AlreadyExistException ex) {
        ErrorMessageDto errorMessage = new ErrorMessageDto(ex.getMessage(), ex.getClass().getSimpleName(), null);
        if (log.isDebugEnabled()) {
            errorMessage.setStacktrace(ExceptionUtils.getStackTrace(ex));
        }
        ApiErrorResponseDto apiErrorResponseDto = new ApiErrorResponseDto(405, HttpStatus.BAD_REQUEST, "Object already exists", errorMessage);
        apiErrorResponseDto.setTimestamp(Instant.now().toEpochMilli());
        log.error("{}", apiErrorResponseDto.getMessage(), ex);
        return new ResponseEntity<>(
                apiErrorResponseDto, new HttpHeaders(), apiErrorResponseDto.getStatus());
    }

    @ExceptionHandler(NotDeletableException.class)
    public ResponseEntity<Object> handleNotDeletableException(NotDeletableException ex) {
        ErrorMessageDto errorMessage = new ErrorMessageDto(ex.getMessage(), ex.getClass().getSimpleName(), null);
        if (log.isDebugEnabled()) {
            errorMessage.setStacktrace(ExceptionUtils.getStackTrace(ex));
        }
        ApiErrorResponseDto apiErrorResponseDto = new ApiErrorResponseDto(406, HttpStatus.BAD_REQUEST, "Object cannot be deleted", errorMessage);
        apiErrorResponseDto.setTimestamp(Instant.now().toEpochMilli());
        log.error("{}", apiErrorResponseDto.getMessage(), ex);
        return new ResponseEntity<>(
                apiErrorResponseDto, new HttpHeaders(), apiErrorResponseDto.getStatus());
    }

    @ExceptionHandler(ValidationException.class)
    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    public List<String> handleValidationException(ValidationException ex) {
        log.info("HTTP 422: {}", ex.getMessage());

        return ex.getErrors().stream()
                .map(ValidationError::getErrorDescription)
                .toList();
    }

    @ExceptionHandler(CryptographicOperationException.class)
    public ResponseEntity<Object> handleCryptographicOperationException(CryptographicOperationException ex) {
        ErrorMessageDto errorMessage = new ErrorMessageDto(ex.getMessage(), ex.getClass().getSimpleName(), null);
        if (log.isDebugEnabled()) {
            errorMessage.setStacktrace(ExceptionUtils.getStackTrace(ex));
        }
        ApiErrorResponseDto apiErrorResponseDto = new ApiErrorResponseDto(702, HttpStatus.BAD_REQUEST, "Cryptographic operation problem", errorMessage);
        apiErrorResponseDto.setTimestamp(Instant.now().toEpochMilli());
        log.error("{}", apiErrorResponseDto.getMessage(), ex);
        return new ResponseEntity<>(
                apiErrorResponseDto, new HttpHeaders(), apiErrorResponseDto.getStatus());
    }

    @ExceptionHandler(TokenInstanceException.class)
    public ResponseEntity<Object> handleTokenInstanceException(TokenInstanceException ex) {
            ErrorMessageDto errorMessage = new ErrorMessageDto(ex.getMessage(), ex.getClass().getSimpleName(), null);
        if (log.isDebugEnabled()) {
            errorMessage.setStacktrace(ExceptionUtils.getStackTrace(ex));
        }
        ApiErrorResponseDto apiErrorResponseDto = new ApiErrorResponseDto(701, HttpStatus.BAD_REQUEST, "Token instance problem", errorMessage);
        apiErrorResponseDto.setTimestamp(Instant.now().toEpochMilli());
        log.error("{}", apiErrorResponseDto.getMessage(), ex);
        return new ResponseEntity<>(
                apiErrorResponseDto, new HttpHeaders(), apiErrorResponseDto.getStatus());
    }

    @ExceptionHandler(NotSupportedException.class)
    @ResponseStatus(HttpStatus.NOT_IMPLEMENTED)
    public ResponseEntity<Object> handleNotSupportedException(NotSupportedException ex) {
        log.debug("HTTP 501: {}", ex.getMessage());
        ErrorMessageDto errorMessage = new ErrorMessageDto(ex.getMessage(), ex.getClass().getSimpleName(), null);
        ApiErrorResponseDto apiErrorResponseDto = new ApiErrorResponseDto(501, HttpStatus.NOT_IMPLEMENTED, "", errorMessage);
        apiErrorResponseDto.setTimestamp(Instant.now().toEpochMilli());
        return new ResponseEntity<>(
                apiErrorResponseDto, new HttpHeaders(), apiErrorResponseDto.getStatus());
    }

    @ExceptionHandler({ Exception.class })
    public ResponseEntity<Object> handleAll(Exception ex) {
        ErrorMessageDto errorMessage = new ErrorMessageDto("Unexpected error", ex.getClass().getSimpleName(), ex.getMessage());
        if (log.isDebugEnabled()) {
            errorMessage.setStacktrace(ExceptionUtils.getStackTrace(ex));
        }
        ApiErrorResponseDto apiErrorResponseDto = new ApiErrorResponseDto(99, HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected exception occurred", errorMessage);
        apiErrorResponseDto.setTimestamp(Instant.now().toEpochMilli());
        log.error("Unexpected exception occurred", ex);
        return new ResponseEntity<>(
                apiErrorResponseDto, new HttpHeaders(), apiErrorResponseDto.getStatus());
    }

}
