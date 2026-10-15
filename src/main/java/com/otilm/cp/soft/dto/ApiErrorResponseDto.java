package com.otilm.cp.soft.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collections;
import java.util.List;
import org.springframework.http.HttpStatus;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiErrorResponseDto {

    private long timestamp;

    private int code;

    private HttpStatus status;

    private String message;

    private List<ErrorMessageDto> errors;

    public ApiErrorResponseDto() {
        super();
    }

    public ApiErrorResponseDto(final int code, final HttpStatus status, final String message,
            final List<ErrorMessageDto> errors) {
        super();
        this.code = code;
        this.status = status;
        this.message = message;
        this.errors = errors;
    }

    public ApiErrorResponseDto(final int code, final HttpStatus status, final String message,
            final ErrorMessageDto error) {
        super();
        this.code = code;
        this.status = status;
        this.message = message;
        this.errors = Collections.singletonList(error);
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    @JsonIgnore
    public HttpStatus getStatus() {
        return status;
    }

    /** The status by name, as v1 has always written it; Jackson 3 would write the enum's text, which adds the code. */
    @JsonProperty("status")
    public String getStatusName() {
        return status == null ? null : status.name();
    }

    public void setStatus(HttpStatus status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public List<ErrorMessageDto> getErrors() {
        return errors;
    }

    public void setErrors(List<ErrorMessageDto> errors) {
        this.errors = errors;
    }
}
