package com.webshield.auth;

/**
 * Thrown by {@link AuthService} when an authentication or authorisation
 * business rule is violated (e.g. bad credentials, duplicate email).
 *
 * <p>Kept as an unchecked exception so callers can choose to handle or
 * propagate it without mandatory try/catch declarations.
 */
public class AuthException extends RuntimeException {

    public AuthException(String message) {
        super(message);
    }

    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}

