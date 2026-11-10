package com.webshield.auth;

import com.webshield.models.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SessionManager Tests")
class SessionManagerTest {

    private SessionManager sessionManager;

    @BeforeEach
    void setUp() {
        sessionManager = SessionManager.getInstance();
        sessionManager.logout(); // ensure clean state
    }

    @AfterEach
    void tearDown() {
        sessionManager.logout();
    }

    @Test
    @DisplayName("Initial session state is unauthenticated")
    void testInitialStateUnauthenticated() {
        assertNull(sessionManager.getCurrentUser(), "Current user should be null initially");
        assertThrows(IllegalStateException.class, () -> sessionManager.requireAuthenticated());
    }

    @Test
    @DisplayName("Login sets the authenticated user")
    void testLoginSetsUser() {
        User user = new User(10, "Security Auditor", "auditor@webshield.io", "hashedPass",
                LocalDateTime.now(), LocalDateTime.now());

        sessionManager.login(user);

        assertNotNull(sessionManager.getCurrentUser());
        assertEquals(10, sessionManager.getCurrentUser().getId());
        assertEquals("auditor@webshield.io", sessionManager.getCurrentUser().getEmail());
        assertEquals("Security Auditor", sessionManager.getCurrentUser().getFullName());
        assertDoesNotThrow(() -> sessionManager.requireAuthenticated());
    }

    @Test
    @DisplayName("Logout clears session and invalidates access")
    void testLogoutClearsSession() {
        User user = new User(1, "Operator", "op@webshield.io", "hash",
                LocalDateTime.now(), LocalDateTime.now());
        sessionManager.login(user);
        assertNotNull(sessionManager.getCurrentUser());

        sessionManager.logout();

        assertNull(sessionManager.getCurrentUser());
        assertThrows(IllegalStateException.class, () -> sessionManager.requireAuthenticated(),
                "Accessing protected area after logout must throw IllegalStateException");
    }

    @Test
    @DisplayName("Access isolation between different users")
    void testUserAccessIsolation() {
        User user1 = new User(1, "User One", "user1@example.com", "hash1",
                LocalDateTime.now(), LocalDateTime.now());
        User user2 = new User(2, "User Two", "user2@example.com", "hash2",
                LocalDateTime.now(), LocalDateTime.now());

        sessionManager.login(user1);
        assertEquals(1, sessionManager.getCurrentUser().getId());
        assertEquals("user1@example.com", sessionManager.getCurrentUser().getEmail());

        // Switch to user 2
        sessionManager.login(user2);
        assertEquals(2, sessionManager.getCurrentUser().getId());
        assertEquals("user2@example.com", sessionManager.getCurrentUser().getEmail());
        assertNotEquals(user1.getId(), sessionManager.getCurrentUser().getId());
    }
}

