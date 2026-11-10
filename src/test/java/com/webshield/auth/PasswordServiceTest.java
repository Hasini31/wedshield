package com.webshield.auth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("PasswordService BCrypt Tests")
class PasswordServiceTest {

    @Test
    @DisplayName("Hashing generates valid BCrypt hash string")
    void testHashPassword() {
        String plain = "Secur3P@ssword";
        String hash = PasswordService.hash(plain);

        assertNotNull(hash);
        assertTrue(hash.startsWith("$2a$") || hash.startsWith("$2b$") || hash.startsWith("$2y$"),
                "BCrypt hash should start with $2");
        assertNotEquals(plain, hash, "Plain text must never equal hash");
    }

    @Test
    @DisplayName("Verify returns true for matching password")
    void testVerifySuccess() {
        String plain = "SuperSecret123!";
        String hash = PasswordService.hash(plain);

        assertTrue(PasswordService.verify(plain, hash));
    }

    @Test
    @DisplayName("Verify returns false for incorrect password")
    void testVerifyFailure() {
        String plain = "CorrectPassword1";
        String wrong = "WrongPassword2";
        String hash = PasswordService.hash(plain);

        assertFalse(PasswordService.verify(wrong, hash));
    }

    @Test
    @DisplayName("Verify returns false on null inputs")
    void testVerifyNullInputs() {
        assertFalse(PasswordService.verify(null, "someHash"));
        assertFalse(PasswordService.verify("somePass", null));
        assertFalse(PasswordService.verify(null, null));
    }

    @Test
    @DisplayName("Hash throws IllegalArgumentException on null input")
    void testHashNullThrows() {
        assertThrows(IllegalArgumentException.class, () -> PasswordService.hash(null));
    }
}

