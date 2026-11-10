package com.webshield.auth;

import com.webshield.models.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the current authenticated session.
 * Implemented as a simple singleton storing the logged‑in {@link User}.
 * All protected UI pages should check {@code SessionManager.getInstance().getCurrentUser()}
 * before allowing access.
 */
public class SessionManager {
    private static final Logger log = LoggerFactory.getLogger(SessionManager.class);
    private static final SessionManager INSTANCE = new SessionManager();
    private User currentUser;

    private SessionManager() {}

    public static SessionManager getInstance() {
        return INSTANCE;
    }

    /** Store the authenticated user */
    public void login(User user) {
        this.currentUser = user;
        log.info("Session started for user id {}", user.getId());
    }

    /** Clear the current session */
    public void logout() {
        if (this.currentUser != null) {
            log.info("Session ended for user id {}", this.currentUser.getId());
        }
        this.currentUser = null;
    }

    /** Return the currently authenticated user, or null if none */
    public User getCurrentUser() {
        return currentUser;
    }

    /** Helper to enforce authentication */
    public void requireAuthenticated() {
        if (currentUser == null) {
            throw new IllegalStateException("User not authenticated");
        }
    }
}

