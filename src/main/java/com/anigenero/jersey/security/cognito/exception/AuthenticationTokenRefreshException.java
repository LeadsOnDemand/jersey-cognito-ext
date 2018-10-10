package com.anigenero.jersey.security.cognito.exception;

public class AuthenticationTokenRefreshException extends RuntimeException {

    public AuthenticationTokenRefreshException(String message) {
        super(message);
    }

    @SuppressWarnings("WeakerAccess")
    public AuthenticationTokenRefreshException(String message, Throwable cause) {
        super(message, cause);
    }

}
