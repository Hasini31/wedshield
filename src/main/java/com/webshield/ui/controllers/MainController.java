package com.webshield.ui.controllers;

import javafx.fxml.FXML;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Legacy main controller retained for compatibility with main.fxml
 * (the initial architecture proof-of-concept layout).
 *
 * <p>All active page navigation is now handled by {@link ShellController}
 * and the per-page controllers under {@code com.webshield.ui.controllers}.</p>
 */
public class MainController {

    private static final Logger log = LoggerFactory.getLogger(MainController.class);

    @FXML
    public void initialize() {
        log.debug("MainController initialised (legacy layout – not in active use)");
    }
}
