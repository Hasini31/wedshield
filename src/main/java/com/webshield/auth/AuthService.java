package com.webshield.auth;

import com.webshield.models.User;
import com.webshield.database.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * High‑level authentication service delegating to lower‑level components.
 * Handles registration (validation, password hashing, duplicate‑email check)
 * and login (credential verification). All DB interaction goes through
 * {@link UserRepository}. Business exceptions are wrapped in {@link AuthException}.
 */
@Service
public class AuthService {
    // AuthException is now a top-level public class in com.webshield.auth
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private final UserRepository userRepo;
    private final AuthValidator validator;

    public AuthService() {
        this(new UserRepository(), new AuthValidator());
    }

    public AuthService(UserRepository userRepo, AuthValidator validator) {
        this.userRepo = userRepo != null ? userRepo : new UserRepository();
        this.validator = validator != null ? validator : new AuthValidator();
    }

    /** Register a new user.
     * @throws AuthException if validation fails or email already exists */
    public User register(String fullName, String email, String password, String confirm) {
        validator.validateFullName(fullName);
        validator.validateEmail(email);
        validator.validatePasswordStrength(password);
        validator.validatePasswordMatch(password, confirm);
        if (userRepo.findByEmail(email).isPresent()) {
            throw new AuthException("Email already registered");
        }
        String hash = PasswordService.hash(password);
        User user = new User();
        user.setFullName(fullName);
        user.setEmail(email);
        user.setPasswordHash(hash);
        userRepo.save(user);
        log.info("Registered new user: {}", email);
        return user;
    }

    /** Attempt login with credentials. Returns authenticated User. */
    public User login(String email, String password) {
        validator.validateEmail(email);
        validator.validateNotBlank(password, "Password");
        User user = userRepo.findByEmail(email)
                .orElseThrow(() -> new AuthException("Invalid credentials"));
        if (!PasswordService.verify(password, user.getPasswordHash())) {
            throw new AuthException("Invalid credentials");
        }
        SessionManager.getInstance().login(user);
        log.info("User logged in: {}", email);
        return user;
    }

    /** Log out the current session. */
    public void logout() {
        SessionManager.getInstance().logout();
        log.info("User logged out");
    }
}

