package com.leadsondemand.jersey.security.cognito.exception;

public class AccessDeniedException extends RuntimeException {

    public AccessDeniedException(String message) {
        super(message);
    }

    @SuppressWarnings("WeakerAccess")
    public AccessDeniedException(String message, Throwable cause) {
        super(message, cause);
    }

}
