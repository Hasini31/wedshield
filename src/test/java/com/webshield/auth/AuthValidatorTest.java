package com.webshield.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AuthValidator Tests")
class AuthValidatorTest {

    private AuthValidator validator;

    @BeforeEach
    void setUp() {
        validator = new AuthValidator();
    }

    @Nested
    @DisplayName("Full Name Validation")
    class FullNameTests {

        @Test
        @DisplayName("Valid full name passes")
        void testValidFullName() {
            assertDoesNotThrow(() -> validator.validateFullName("Alice Smith"));
            assertDoesNotThrow(() -> validator.validateFullName("Bob"));
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "A", "AB"})
        @DisplayName("Blank or too short full name throws IllegalArgumentException")
        void testInvalidFullName(String name) {
            assertThrows(IllegalArgumentException.class, () -> validator.validateFullName(name));
        }
    }

    @Nested
    @DisplayName("Email Validation")
    class EmailTests {

        @ParameterizedTest
        @ValueSource(strings = {
            "test@example.com",
            "user.name@sub.domain.org",
            "security+audit@company.co",
            "admin_123@webshield.io"
        })
        @DisplayName("Valid email formats pass")
        void testValidEmails(String email) {
            assertDoesNotThrow(() -> validator.validateEmail(email));
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {
            "not-an-email",
            "@missing-local.com",
            "missing-at-sign.com",
            "user@.com",
            "user@domain",
            "user@domain."
        })
        @DisplayName("Invalid email formats throw IllegalArgumentException")
        void testInvalidEmails(String email) {
            assertThrows(IllegalArgumentException.class, () -> validator.validateEmail(email));
        }
    }

    @Nested
    @DisplayName("Password Strength Validation")
    class PasswordStrengthTests {

        @ParameterizedTest
        @ValueSource(strings = {
            "ValidP@ssw0rd",
            "Secur3Pass!",
            "Admin#2024Web",
            "Password123"
        })
        @DisplayName("Strong passwords pass validation")
        void testStrongPasswords(String password) {
            assertDoesNotThrow(() -> validator.validatePasswordStrength(password));
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {
            "Short1A",          // < 8 chars
            "nouppercase123",   // missing uppercase
            "NOLOWERCASE123",   // missing lowercase
            "NoDigitsInPassword",// missing digit
            "12345678"          // no letters
        })
        @DisplayName("Weak passwords throw IllegalArgumentException")
        void testWeakPasswords(String password) {
            assertThrows(IllegalArgumentException.class, () -> validator.validatePasswordStrength(password));
        }
    }

    @Nested
    @DisplayName("Password Match Validation")
    class PasswordMatchTests {

        @Test
        @DisplayName("Matching passwords pass")
        void testMatchingPasswords() {
            assertDoesNotThrow(() -> validator.validatePasswordMatch("Secret123", "Secret123"));
        }

        @Test
        @DisplayName("Mismatched passwords throw IllegalArgumentException")
        void testMismatchedPasswords() {
            assertThrows(IllegalArgumentException.class, () -> validator.validatePasswordMatch("Secret123", "Different456"));
        }
    }
}

