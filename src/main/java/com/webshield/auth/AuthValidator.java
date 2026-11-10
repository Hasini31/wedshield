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
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }
        if (!password.matches(".*[A-Z].*") || !password.matches(".*[a-z].*") || !password.matches(".*\\d.*")) {
            throw new IllegalArgumentException("Password must contain upper‑case, lower‑case letters and a digit");
        }
    }

    public void validatePasswordMatch(String password, String confirm) {
        if (!password.equals(confirm)) {
            throw new IllegalArgumentException("Passwords do not match");
        }
    }
}

