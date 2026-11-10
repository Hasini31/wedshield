package com.webshield.auth;

import org.springframework.stereotype.Component;

/**
 * Simple wrapper around BCrypt for password hashing and verification.
 * Uses the JBCrypt library (org.mindrot:jbcrypt).
 */
@Component
public class PasswordService {
    /**
     * Generate a BCrypt hash for the given plain password.
     * @param plainPassword the password to hash (must not be null)
     * @return BCrypt hash string
     */
    public static String hash(String plainPassword) {
        if (plainPassword == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        // Default log rounds = 12 (secure and fast enough for demo)
        return org.mindrot.jbcrypt.BCrypt.hashpw(plainPassword, org.mindrot.jbcrypt.BCrypt.gensalt(12));
    }

    /**
     * Verify a plain password against a stored BCrypt hash.
     * @param plainPassword password supplied by user
     * @param hashedPassword stored BCrypt hash
     * @return true if matches
     */
    public static boolean verify(String plainPassword, String hashedPassword) {
        if (plainPassword == null || hashedPassword == null) {
            return false;
        }
        return org.mindrot.jbcrypt.BCrypt.checkpw(plainPassword, hashedPassword);
    }
}

