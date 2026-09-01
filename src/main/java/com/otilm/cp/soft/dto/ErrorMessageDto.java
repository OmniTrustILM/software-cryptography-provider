package com.otilm.cp.soft.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorMessageDto {

    private String error;

    private String type;

    private String detail;

    private String stacktrace;

    public ErrorMessageDto() {
        super();
    }

    public ErrorMessageDto(String error, String type, String detail) {
        this.error = error;
        this.type = type;
        this.detail = detail;
    }

    public ErrorMessageDto(String error, String type, String detail, String stacktrace) {
        this.error = error;
        this.type = type;
        this.detail = detail;
        this.stacktrace = stacktrace;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public String getStacktrace() {
        return stacktrace;
    }

    public void setStacktrace(String stacktrace) {
        this.stacktrace = stacktrace;
    }
}
