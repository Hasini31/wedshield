package com.webshield.auth;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Validates user input for authentication flows.
 * Throws {@link IllegalArgumentException} with a descriptive message when
 * validation fails.
 */
@Component
public class AuthValidator {
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$",
            Pattern.CASE_INSENSITIVE);

    public void validateNotBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be empty");
        }
    }

    public void validateFullName(String fullName) {
        validateNotBlank(fullName, "Full name");
        if (fullName.length() < 3) {
            throw new IllegalArgumentException("Full name must contain at least 3 characters");
        }
    }

    public void validateEmail(String email) {
        validateNotBlank(email, "Email");
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            throw new IllegalArgumentException("Invalid email format");
        }
    }

    public void validatePasswordStrength(String password) {
        validateNotBlank(password, "Password");
        if (password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
        if (!password.matches(".*[A-Z].*")) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter (A-Z)");
        }
        if (!password.matches(".*[a-z].*")) {
            throw new IllegalArgumentException("Password must contain at least one lowercase letter (a-z)");
        }
        if (!password.matches(".*\\d.*")) {
            throw new IllegalArgumentException("Password must contain at least one number (0-9)");
        }
        if (!password.matches(".*[^a-zA-Z0-9].*")) {
            throw new IllegalArgumentException("Password must contain at least one special symbol (e.g. !@#$%^&*()_+-=)");
        }
    }

    public void validatePasswordMatch(String password, String confirm) {
        if (!password.equals(confirm)) {
            throw new IllegalArgumentException("Passwords do not match");
        }
    }
}

